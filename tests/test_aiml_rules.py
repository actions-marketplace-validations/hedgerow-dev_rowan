"""Tests for MFV model file scanner and expanded AI/ML rules."""

import json
import pickle
import struct
from pathlib import Path

import pytest
from hayward import ModelFileScanner

from rowan.core.findings import Severity
from rowan.core.rules import load_neuroscan_rules


def _build_gguf(kvs: list[tuple[bytes, bytes]]) -> bytes:
    """Build a minimal, structurally-valid GGUF file with only string-typed
    metadata KV entries (value_type=8), matching what the real GGUF spec's
    header + KV section looks like -- so the scanner's structure-aware
    parser (_parse_gguf_metadata) can actually walk it."""

    def gguf_string(s: bytes) -> bytes:
        return struct.pack("<Q", len(s)) + s

    header = b"GGUF" + struct.pack("<IQQ", 3, 0, len(kvs))
    body = b"".join(gguf_string(k) + struct.pack("<I", 8) + gguf_string(v) for k, v in kvs)
    return header + body


def _build_keras_h5(model_config: dict) -> bytes:
    """Build a fake-but-parseable Keras H5 file: real HDF5 magic followed by
    the model_config JSON blob, matching how a real Keras H5 file embeds its
    architecture as a literal JSON attribute value (and how the scanner's
    _extract_keras_model_config locates it)."""
    blob = json.dumps(model_config).encode("utf-8")
    return b"\x89HDF\r\n\x1a\n" + b"\x00" * 32 + blob + b"\x00" * 16


class TestModelFileScanner:
    def test_pickle_backdoor_detection(self, tmp_path):
        """Detect __reduce__ in pickle files."""
        scanner = ModelFileScanner()

        # Create a benign pickle with reduce
        class Evil:
            def __reduce__(self):
                return (exec, ("print('pwned')",))

        path = tmp_path / "backdoor.pkl"
        with open(path, "wb") as f:
            pickle.dump(Evil(), f)

        findings = scanner.scan_file(path)
        assert len(findings) > 0
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) > 0

    def test_clean_pickle_passes(self, tmp_path):
        """Clean pickle with no reduce should get INFO only."""
        scanner = ModelFileScanner()

        path = tmp_path / "clean.pkl"
        with open(path, "wb") as f:
            pickle.dump({"a": 1, "b": 2}, f)

        findings = scanner.scan_file(path)
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical) == 0

    def test_pickle_bytescan_detection(self, tmp_path):
        """Raw byte scan catches __reduce__ even if pickletools can't parse."""
        scanner = ModelFileScanner()

        path = tmp_path / "evil.pt"
        path.write_bytes(b"__reduce__" + b"\x00" * 100)

        findings = scanner.scan_file(path)
        assert any("suspicious byte patterns" in f.message for f in findings)

    def test_safetensors_header_validation(self, tmp_path):
        """Validate SafeTensors format integrity."""
        scanner = ModelFileScanner()

        # Valid SafeTensors: 8-byte header size + JSON header
        header = b'{"test": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]}}'
        data = struct.pack("<Q", len(header)) + header + b"\x00" * 24

        path = tmp_path / "model.safetensors"
        path.write_bytes(data)

        findings = scanner.scan_file(path)
        assert len(findings) == 0  # Clean SafeTensors produces no findings

    def test_safetensors_suspicious_metadata(self, tmp_path):
        """Flag suspicious keys in SafeTensors metadata."""
        scanner = ModelFileScanner()

        header = b'{"__metadata__": {"__reduce__": "evil"}, "tensor": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}'
        data = struct.pack("<Q", len(header)) + header + b"\x00" * 4

        path = tmp_path / "evil.safetensors"
        path.write_bytes(data)

        findings = scanner.scan_file(path)
        assert any("suspicious keys" in f.message for f in findings)

    def test_safetensors_too_small(self, tmp_path):
        scanner = ModelFileScanner()
        path = tmp_path / "tiny.safetensors"
        path.write_bytes(b"\x00" * 4)
        findings = scanner.scan_file(path)
        assert any("too small" in f.message for f in findings)

    def test_gguf_magic_validation(self, tmp_path):
        scanner = ModelFileScanner()
        path = tmp_path / "model.gguf"
        # A structurally valid empty GGUF: version 3, zero tensors, zero KV.
        # (The old fixture was magic + zero bytes, which is not a valid GGUF
        # at any version: version 0 does not exist in the spec, and the
        # layout-arithmetic pass correctly flags it.)
        path.write_bytes(b"GGUF" + struct.pack("<IQQ", 3, 0, 0))
        findings = scanner.scan_file(path)
        assert len(findings) == 0  # Clean GGUF produces no findings

    def test_gguf_invalid_magic(self, tmp_path):
        scanner = ModelFileScanner()
        path = tmp_path / "fake.gguf"
        path.write_bytes(b"FAKE" + b"\x00" * 100)
        findings = scanner.scan_file(path)
        assert any("magic number invalid" in f.message for f in findings)

    def test_gguf_chat_template_ssti(self, tmp_path):
        """GGUF with Jinja2 SSTI payload in the actual tokenizer.chat_template
        metadata value (real GGUF KV structure, not a raw substring)."""
        scanner = ModelFileScanner()
        path = tmp_path / "evil.gguf"
        content = _build_gguf([
            (b"general.name", b"evil-model"),
            (b"tokenizer.chat_template", b"{{ 7*7 }} {{ lipsum.__globals__ }}"),
        ])
        path.write_bytes(content)
        findings = scanner.scan_file(path)
        assert any("chat_template" in f.message and "Jinja2" in f.message for f in findings)

    def test_gguf_clean_chat_template_not_flagged(self, tmp_path):
        """An ordinary (non-Jinja2) chat_template and prose description must
        not be flagged -- the old substring scanner would have false-positived
        on "subprocess" anywhere in the file, including free-text fields."""
        scanner = ModelFileScanner()
        path = tmp_path / "benign.gguf"
        content = _build_gguf([
            (b"general.name", b"my-model"),
            (b"general.description", b"Trained with a subprocess-based preprocessing pipeline"),
            (b"tokenizer.chat_template", b"System: {role}\nUser: {content}"),
        ])
        path.write_bytes(content)
        findings = scanner.scan_file(path)
        assert findings == []

    def test_keras_lambda_detection(self, tmp_path):
        """A real Lambda layer in the parsed model_config layer graph must be
        flagged (not a raw substring match on the word "lambda")."""
        scanner = ModelFileScanner()
        path = tmp_path / "model.h5"
        config = {
            "class_name": "Sequential",
            "config": {"name": "seq", "layers": [
                {"class_name": "InputLayer", "config": {"name": "input_1"}},
                {"class_name": "Lambda", "config": {"name": "backdoor"}},
            ]},
        }
        path.write_bytes(_build_keras_h5(config))
        findings = scanner.scan_file(path)
        assert any("Lambda layer" in f.message for f in findings)
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_keras_benign_activation_function_not_flagged(self, tmp_path):
        """A normal Dense layer whose config mentions "function"/"lambda" only
        as substrings of unrelated words (e.g. an "activation" config) must
        not be flagged -- this was the scanner's main false-positive mode."""
        scanner = ModelFileScanner()
        path = tmp_path / "benign.h5"
        config = {
            "class_name": "Sequential",
            "config": {"name": "seq", "layers": [
                {"class_name": "InputLayer", "config": {"name": "input_1"}},
                {"class_name": "Dense", "config": {"name": "dense_1", "activation": "relu"}},
            ]},
        }
        path.write_bytes(_build_keras_h5(config))
        findings = scanner.scan_file(path)
        assert findings == []

    def test_scan_directory(self, tmp_path):
        scanner = ModelFileScanner()

        # Create a mix of model files: clean pickle, broken safetensors
        (tmp_path / "clean.pkl").write_bytes(pickle.dumps({"a": 1}))
        (tmp_path / "model.safetensors").write_bytes(
            struct.pack("<Q", 50)
            + b'{"tensor": {"dtype": "F32", "shape": [1], "data_offsets": [0, 4]}}'
            + b"\x00" * 4
        )

        findings = scanner.scan_directory(tmp_path)
        # Clean pickle produces no findings; broken safetensors (header extends
        # past EOF because header_size=50 > actual content) produces one finding
        assert len(findings) >= 1

    def test_unknown_format_skipped(self, tmp_path):
        scanner = ModelFileScanner()
        path = tmp_path / "data.bin"
        path.write_bytes(b"\x00" * 100)
        findings = scanner.scan_file(path)
        assert len(findings) == 0


class TestModelFormatConfusion:
    """MFV-CONFUSE-001 (issue #152): a file whose *content* matches a
    different ModelFormat than its extension implies must not be waved
    through as merely 'corrupted' -- several real loaders (torch.load,
    safetensors readers, GGUF loaders) sniff magic bytes rather than
    trusting the extension, so a mismatched file is still exploitable
    downstream even though the extension-directed scanner failed to parse
    it as its nominal format.
    """

    def test_pickle_saved_as_safetensors_detected_and_rescanned(self, tmp_path):
        """A real backdoored pickle stream saved with a .safetensors
        extension must fire MFV-CONFUSE-001 *and* actually get scanned as a
        pickle -- not just flagged as a mismatch and dropped."""
        scanner = ModelFileScanner()

        class Evil:
            def __reduce__(self):
                return (exec, ("print('pwned')",))

        path = tmp_path / "model.safetensors"
        with open(path, "wb") as f:
            pickle.dump(Evil(), f)

        findings = scanner.scan_file(path)

        confuse = [f for f in findings if f.rule_id == "MFV-CONFUSE-001"]
        assert len(confuse) == 1
        assert confuse[0].severity == Severity.HIGH
        assert confuse[0].category.value == "ai_ml"
        assert confuse[0].metadata["extension_format"] == "safetensors"
        assert confuse[0].metadata["sniffed_format"] == "pickle"

        # The sniffed-format re-scan must have actually run: the pickle's
        # real __reduce__-based backdoor should surface as its own finding,
        # not just the confusion notice.
        assert any(f.rule_id == "MFV-PICKLE-001" and f.severity == Severity.CRITICAL for f in findings)

    def test_gguf_saved_as_pkl_detected_and_rescanned(self, tmp_path):
        """A real GGUF file saved with a .pkl extension must fire
        MFV-CONFUSE-001 and get re-scanned with the GGUF metadata scanner."""
        scanner = ModelFileScanner()
        path = tmp_path / "model.pkl"
        content = _build_gguf([
            (b"general.name", b"evil-model"),
            (b"tokenizer.chat_template", b"{{ 7*7 }} {{ lipsum.__globals__ }}"),
        ])
        path.write_bytes(content)

        findings = scanner.scan_file(path)

        confuse = [f for f in findings if f.rule_id == "MFV-CONFUSE-001"]
        assert len(confuse) == 1
        assert confuse[0].metadata["extension_format"] == "pickle"
        assert confuse[0].metadata["sniffed_format"] == "gguf"

        # The sniffed GGUF re-scan must have actually run and caught the
        # real SSTI payload in the chat_template metadata.
        assert any("chat_template" in f.message and "Jinja2" in f.message for f in findings)

    def test_corrupted_safetensors_does_not_fire_confuse(self, tmp_path):
        """A genuinely corrupted (too-small) SafeTensors file must keep the
        plain 'corrupted' finding and must NOT fabricate a format mismatch --
        its bytes don't match any other known ModelFormat signature."""
        scanner = ModelFileScanner()
        path = tmp_path / "tiny.safetensors"
        path.write_bytes(b"\x00" * 4)
        findings = scanner.scan_file(path)
        assert any("too small" in f.message for f in findings)
        assert not any(f.rule_id == "MFV-CONFUSE-001" for f in findings)

    def test_corrupted_gguf_does_not_fire_confuse(self, tmp_path):
        """A file with an invalid GGUF magic (but not matching any other
        known format either) must not fire MFV-CONFUSE-001."""
        scanner = ModelFileScanner()
        path = tmp_path / "fake.gguf"
        path.write_bytes(b"FAKE" + b"\x00" * 100)
        findings = scanner.scan_file(path)
        assert any("magic number invalid" in f.message for f in findings)
        assert not any(f.rule_id == "MFV-CONFUSE-001" for f in findings)

    def test_corrupted_pickle_does_not_fire_confuse(self, tmp_path):
        """Random bytes with a .pkl extension that don't parse as pickle
        opcodes AND don't match any other known format must not fire
        MFV-CONFUSE-001 -- just corrupted, nothing to re-scan as."""
        scanner = ModelFileScanner()
        path = tmp_path / "garbage.pkl"
        path.write_bytes(bytes(range(256)) * 4)  # arbitrary non-pickle, non-magic bytes
        findings = scanner.scan_file(path)
        assert not any(f.rule_id == "MFV-CONFUSE-001" for f in findings)

    def test_corrupted_keras_does_not_fire_confuse(self, tmp_path):
        """Bytes that are neither valid HDF5 nor a valid zip must not fire
        MFV-CONFUSE-001 against a .h5 extension."""
        scanner = ModelFileScanner()
        path = tmp_path / "broken.h5"
        path.write_bytes(b"not an hdf5 or zip file" + b"\x00" * 40)
        findings = scanner.scan_file(path)
        assert not any(f.rule_id == "MFV-CONFUSE-001" for f in findings)

    def test_corrupted_npy_does_not_fire_confuse(self, tmp_path):
        """Bytes with a .npy extension but no NUMPY magic and no other
        format match must not fire MFV-CONFUSE-001."""
        scanner = ModelFileScanner()
        path = tmp_path / "broken.npy"
        path.write_bytes(b"not a numpy file" + b"\x00" * 40)
        findings = scanner.scan_file(path)
        assert not any(f.rule_id == "MFV-CONFUSE-001" for f in findings)

    def test_clean_safetensors_extension_not_flagged(self, tmp_path):
        """A well-formed SafeTensors file (matching its own extension) must
        never fire MFV-CONFUSE-001 -- the sniff is only reachable when the
        extension-directed parse already failed."""
        scanner = ModelFileScanner()
        header = b'{"test": {"dtype": "F32", "shape": [2, 3], "data_offsets": [0, 24]}}'
        data = struct.pack("<Q", len(header)) + header + b"\x00" * 24
        path = tmp_path / "clean.safetensors"
        path.write_bytes(data)
        findings = scanner.scan_file(path)
        assert findings == []

    def test_clean_gguf_extension_not_flagged(self, tmp_path):
        """A well-formed GGUF file (matching its own extension) must never
        fire MFV-CONFUSE-001."""
        scanner = ModelFileScanner()
        path = tmp_path / "clean.gguf"
        path.write_bytes(_build_gguf([(b"general.name", b"my-model")]))
        findings = scanner.scan_file(path)
        assert not any(f.rule_id == "MFV-CONFUSE-001" for f in findings)


class TestAIMLRuleAccuracy:
    """Verify AI/ML rules catch intended vulns and skip safe patterns."""

    def rules_dir(self):
        return Path(__file__).parent.parent / "rules"

    def test_ssti_029_catches_unsandboxed_template(self, tmp_path):
        """NS-AIML-029 should flag Template(chat_template) without sandbox."""
        rules = load_neuroscan_rules(self.rules_dir() / "ai_ml_neuroscan.yaml")
        rule_029 = [r for r in rules if r.metadata.id == "NS-AIML-029"]
        if not rule_029:
            pytest.fail("NS-AIML-029 not found")
        rule = rule_029[0]

        # Vulnerable: Template(self.chat_template) without sandbox
        f = tmp_path / "vuln.py"
        f.write_text("""
from jinja2 import Template
chat_template = "..."
self.chat_template_jinja = Template(self.chat_template)
""")
        findings = rule.check(f)
        assert len(findings) >= 1
        assert findings[0].rule_id == "NS-AIML-029"

    def test_ssti_029_skips_sandboxed(self, tmp_path):
        """NS-AIML-029 should NOT flag sandboxed uses."""
        rules = load_neuroscan_rules(self.rules_dir() / "ai_ml_neuroscan.yaml")
        rule_029 = [r for r in rules if r.metadata.id == "NS-AIML-029"]
        if not rule_029:
            pytest.fail("NS-AIML-029 not found")
        rule = rule_029[0]

        # Safe: uses ImmutableSandboxedEnvironment
        f = tmp_path / "safe.py"
        f.write_text("""
from jinja2.sandbox import ImmutableSandboxedEnvironment
env = ImmutableSandboxedEnvironment()
self.chat_template_jinja = env.from_string(self.chat_template)
""")
        findings = rule.check(f)
        assert len(findings) == 0

    def test_ssti_029_skips_function_call_template(self, tmp_path):
        """NS-AIML-029 should NOT match function_call_template()."""
        rules = load_neuroscan_rules(self.rules_dir() / "ai_ml_neuroscan.yaml")
        rule_029 = [r for r in rules if r.metadata.id == "NS-AIML-029"]
        if not rule_029:
            pytest.fail("NS-AIML-029 not found")
        rule = rule_029[0]

        f = tmp_path / "vllm.py"
        f.write_text("""
def function_call_template(chat_template):
    return _load_chat_template(chat_template, is_literal=True)

result = function_call_template(chat_template)
""")
        findings = rule.check(f)
        assert len(findings) == 0

    def test_aiml_001_catches_trust_remote_code(self, tmp_path):
        rules = load_neuroscan_rules(self.rules_dir() / "neuroscan.yaml")
        rule_001 = [r for r in rules if r.metadata.id == "NS-AIML-001"]
        if not rule_001:
            pytest.fail("NS-AIML-001 not found")
        rule = rule_001[0]

        f = tmp_path / "config.py"
        f.write_text("model = AutoModel.from_pretrained('gpt2', trust_remote_code=True)")
        findings = rule.check(f)
        assert len(findings) >= 1

    def test_aiml_030_catches_torch_load_no_weights_only(self, tmp_path):
        rules = load_neuroscan_rules(self.rules_dir() / "ai_security.yaml")
        rule_003 = [r for r in rules if r.metadata.id == "ns-aiml-030"]
        if not rule_003:
            pytest.fail("ns-aiml-030 not found")
        rule = rule_003[0]

        f = tmp_path / "loader.py"
        f.write_text("model = torch.load('model.pt')")
        findings = rule.check(f)
        assert len(findings) >= 1

    def test_aiml_030_skips_weights_only(self, tmp_path):
        rules = load_neuroscan_rules(self.rules_dir() / "ai_security.yaml")
        rule_003 = [r for r in rules if r.metadata.id == "ns-aiml-030"]
        if not rule_003:
            pytest.fail("ns-aiml-030 not found")
        rule = rule_003[0]

        f = tmp_path / "safe.py"
        f.write_text("model = torch.load('model.pt', weights_only=True)")
        findings = rule.check(f)
        assert len(findings) == 0


class TestIssue137DeserializationGaps:
    """Issue #137: datasets.load_dataset trust_remote_code messaging, Keras
    load_model Lambda layers (CVE-2024-3660), enable_unsafe_deserialization."""

    def rules_dir(self):
        return Path(__file__).parent.parent / "rules"

    def _rule(self, rule_id):
        rules = load_neuroscan_rules(self.rules_dir() / "ai_security.yaml")
        matches = [r for r in rules if r.metadata.id == rule_id]
        assert matches, f"{rule_id} not found in ai_security.yaml"
        return matches[0]

    # -- ns-aiml-059 / ns-aiml-113: load_dataset trust_remote_code split --

    def test_059_still_catches_model_repo_trust_remote_code(self, tmp_path):
        rule = self._rule("ns-aiml-059")
        f = tmp_path / "model.py"
        f.write_text("model = AutoModel.from_pretrained('org/model', trust_remote_code=True)")
        findings = rule.check(f)
        assert len(findings) == 1
        assert "model repositories" in findings[0].message

    def test_059_skips_load_dataset_line(self, tmp_path):
        """ns-aiml-059 must not also fire on a load_dataset(..., trust_remote_code=True)
        line -- ns-aiml-113 owns that case, avoiding a duplicate finding (issue #90)."""
        rule = self._rule("ns-aiml-059")
        f = tmp_path / "data.py"
        f.write_text('ds = load_dataset("some/user-dataset", trust_remote_code=True)')
        findings = rule.check(f)
        assert findings == []

    def test_113_catches_load_dataset_trust_remote_code(self, tmp_path):
        rule = self._rule("ns-aiml-113")
        f = tmp_path / "data.py"
        f.write_text('ds = load_dataset("some/user-dataset", trust_remote_code=True)')
        findings = rule.check(f)
        assert len(findings) == 1
        assert "load_dataset" in findings[0].message
        assert "model repositories" not in findings[0].message

    def test_113_and_059_never_both_fire_on_same_line(self, tmp_path):
        """Duplicate-finding acceptance criterion (#90): a line matching both
        the generic and dataset-specific patterns must produce exactly one finding."""
        rule_059 = self._rule("ns-aiml-059")
        rule_113 = self._rule("ns-aiml-113")
        f = tmp_path / "data.py"
        f.write_text(
            'ds = datasets.load_dataset("some/user-dataset", split="train", '
            'trust_remote_code=True)\n'
        )
        findings = rule_059.check(f) + rule_113.check(f)
        assert len(findings) == 1
        assert findings[0].rule_id == "ns-aiml-113"

    def test_113_does_not_fire_without_load_dataset(self, tmp_path):
        rule = self._rule("ns-aiml-113")
        f = tmp_path / "model.py"
        f.write_text("model = AutoModel.from_pretrained('org/model', trust_remote_code=True)")
        assert rule.check(f) == []

    # -- ns-aiml-114 / ns-aiml-115: keras load_model / CVE-2024-3660 --

    def test_114_catches_load_model_on_untrusted_path(self, tmp_path):
        rule = self._rule("ns-aiml-114")
        f = tmp_path / "app.py"
        f.write_text('model = keras.models.load_model(request.files["model"].filename)')
        findings = rule.check(f)
        assert len(findings) == 1
        assert "CVE-2024-3660" in findings[0].message

    def test_114_catches_tf_keras_and_saving_variants(self, tmp_path):
        rule = self._rule("ns-aiml-114")
        f = tmp_path / "app.py"
        f.write_text(
            "m1 = tf.keras.models.load_model(user_path)\n"
            "m2 = keras.saving.load_model(user_path)\n"
        )
        findings = rule.check(f)
        assert len(findings) == 2

    def test_114_skips_safe_mode_false_line(self, tmp_path):
        """safe_mode=False is the explicit-escalation case owned by ns-aiml-115;
        ns-aiml-114 must not double-fire on the same line."""
        rule = self._rule("ns-aiml-114")
        f = tmp_path / "app.py"
        f.write_text('model = keras.models.load_model("local.h5", safe_mode=False)')
        assert rule.check(f) == []

    def test_115_catches_explicit_safe_mode_false(self, tmp_path):
        rule = self._rule("ns-aiml-115")
        f = tmp_path / "app.py"
        f.write_text('model = keras.models.load_model("local.h5", safe_mode=False)')
        findings = rule.check(f)
        assert len(findings) == 1
        # NOTE: not asserting Severity.HIGH here -- ai_security.yaml's
        # `severity: ERROR` is supposed to map to Severity.HIGH via
        # _parse_neuroscan_rule's severity_map, but a pre-existing bug in
        # that function (Severity(raw_severity) is evaluated eagerly as
        # dict.get's default argument, raising ValueError for "error"/
        # "warning" before the map lookup can return, so both silently fall
        # back to Severity.MEDIUM) means it currently maps to MEDIUM instead.
        # This affects every ERROR/WARNING NeuroScan regex rule in the repo,
        # not just this one -- out of scope for issue #137, flagged separately.
        assert findings[0].rule_id == "ns-aiml-115"

    def test_114_and_115_never_both_fire_on_same_line(self, tmp_path):
        rule_114 = self._rule("ns-aiml-114")
        rule_115 = self._rule("ns-aiml-115")
        f = tmp_path / "app.py"
        f.write_text('model = keras.models.load_model("local.h5", safe_mode=False)')
        findings = rule_114.check(f) + rule_115.check(f)
        assert len(findings) == 1
        assert findings[0].rule_id == "ns-aiml-115"

    # -- ns-aiml-116: enable_unsafe_deserialization --

    def test_116_catches_enable_unsafe_deserialization(self, tmp_path):
        rule = self._rule("ns-aiml-116")
        f = tmp_path / "app.py"
        f.write_text("keras.config.enable_unsafe_deserialization()")
        findings = rule.check(f)
        assert len(findings) == 1

    # -- ns-aiml-117: Lambda layer nudge --

    def test_117_catches_lambda_layer(self, tmp_path):
        rule = self._rule("ns-aiml-117")
        f = tmp_path / "train.py"
        f.write_text("layer = Lambda(lambda x: x + 1)")
        findings = rule.check(f)
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO

    def test_117_skips_non_lambda_layers(self, tmp_path):
        rule = self._rule("ns-aiml-117")
        f = tmp_path / "train.py"
        f.write_text("layer = Dense(64, activation='relu')")
        assert rule.check(f) == []

    # -- MFV cross-reference (issue #77 model-file scanner path) --

    def test_mfv_keras_lambda_detection_still_covers_h5(self, tmp_path):
        """ns-aiml-114's message cross-references MFV-KERAS-001; confirm that
        rule actually flags a Lambda layer inside a .h5 archive (same fixture
        shape as TestModelFileScanner.test_keras_lambda_detection)."""
        from hayward import ModelFileScanner

        scanner = ModelFileScanner()
        path = tmp_path / "model.h5"
        config = {
            "class_name": "Sequential",
            "config": {"name": "seq", "layers": [
                {"class_name": "InputLayer", "config": {"name": "input_1"}},
                {"class_name": "Lambda", "config": {"name": "backdoor"}},
            ]},
        }
        path.write_bytes(_build_keras_h5(config))
        findings = scanner.scan_file(path)
        assert any(f.rule_id == "MFV-KERAS-001" for f in findings)


class TestCaseSensitivity:
    """Verify case sensitivity works correctly after the fix."""

    def test_sensitive_pattern_case_matters(self, tmp_path):
        """Template( should match Template( but not template(."""
        import re

        # Case sensitive (default now)
        pat = re.compile(r"\bTemplate\(")
        assert pat.search("Template(chat_template)")
        assert not pat.search("function_call_template(chat_template)")

    def test_insensitive_pattern_still_works(self, tmp_path):
        """(?i) patterns should still be case insensitive."""
        import re

        pat = re.compile(r"apikey", re.IGNORECASE)
        assert pat.search("APIKEY")
        assert pat.search("apikey")
        assert pat.search("ApiKey")


class TestCrossLanguageFalsePositives:
    """Verify language-specific rules don't fire on wrong languages."""

    def test_ruby_eval_not_in_python(self, tmp_path):
        """Ruby eval rule should only fire on .rb files, not .py."""
        # The rule is labeled for [ruby] but the file_scan pass
        # filters by extension. Test that the rule has the right language.
        rules = load_neuroscan_rules(
            Path(__file__).parent.parent / "rules" / "ruby.yaml"
        )
        for r in rules:
            assert "ruby" in r.metadata.languages

    def test_java_rules_only_java(self, tmp_path):
        rules = load_neuroscan_rules(
            Path(__file__).parent.parent / "rules" / "java.yaml"
        )
        for r in rules:
            assert "java" in r.metadata.languages

    def test_go_rules_only_go(self, tmp_path):
        rules = load_neuroscan_rules(
            Path(__file__).parent.parent / "rules" / "go.yaml"
        )
        for r in rules:
            assert "go" in r.metadata.languages

    def test_all_rules_have_language_tags(self):
        """Every rule should specify its target languages."""
        rules_dir = Path(__file__).parent.parent / "rules"
        for yf in rules_dir.glob("*.yaml"):
            if "_taint" in yf.name:  # Skip Opengrep taint rules
                continue
            rules = load_neuroscan_rules(yf)
            for r in rules:
                assert len(r.metadata.languages) > 0, (
                    f"Rule {r.metadata.id} in {yf.name} has no languages"
                )

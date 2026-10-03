"""Positive/negative fixtures for TNT-DESER-007 (rules/ai_ml_taint.yaml, issue
#291): msgpack object/ext-hook reconstruction on checkpoint load
(CVE-2026-28277).

The rule fires only when the msgpack decode carries an object_hook/ext_hook (or a
custom serializer's own .loads) on untrusted bytes -- a bare
`msgpack.unpackb(data)` into plain dicts is memory-safe and must NOT fire
(BACKLOG DEF-11). The pickle-fallback shape stays with ns-aiml-041; the
disjointness control (test_pickle_fallback_*) proves the split.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id, rule_file="ai_ml_taint.yaml"):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / rule_file], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestMsgpackObjectHookTNTDESER007:
    """TNT-DESER-007: untrusted checkpoint bytes -> hook-carrying msgpack decode."""

    def test_object_hook_file_read_flagged(self, tmp_path):
        """Acceptance (a): checkpoint bytes -> unpackb(..., object_hook=...)."""
        src = (
            "def load_checkpoint(path):\n"
            "    with open(path, 'rb') as f:\n"
            "        data = f.read()\n"
            "    return msgpack.unpackb(data, object_hook=reconstruct, raw=False)\n"
        )
        findings = _scan(tmp_path, "object_hook.py", src, "TNT-DESER-007")
        assert findings, "unpackb with object_hook on untrusted bytes must be flagged"

    def test_ext_hook_redis_blob_flagged(self, tmp_path):
        """Generality: a Redis-stored blob (not a file, different names,
        ext_hook via Unpacker instead of unpackb) must still fire."""
        src = (
            "def restore(redis_conn, thread_id):\n"
            "    blob = redis_conn.get(thread_id)\n"
            "    unpacker = msgpack.Unpacker(blob, ext_hook=decode_ext)\n"
            "    return list(unpacker)\n"
        )
        findings = _scan(tmp_path, "ext_hook_redis.py", src, "TNT-DESER-007")
        assert findings, "Unpacker(ext_hook=) on an untrusted blob must generalize beyond LangGraph"

    def test_serializer_loads_flagged(self, tmp_path):
        """A custom serializer's own loads (LangGraph JsonPlusSerializer class)
        on a request body is the custom-serializer reconstruction path."""
        src = (
            "def deserialize(request, serializer):\n"
            "    body = request.body\n"
            "    return serializer.loads(body)\n"
        )
        findings = _scan(tmp_path, "jsonplus.py", src, "TNT-DESER-007")
        assert findings, "a custom serializer's .loads on an untrusted body must be flagged"

    def test_bare_unpackb_no_hook_not_flagged(self, tmp_path):
        """Acceptance (b) + DEF-11: a hookless decode into plain dicts is
        memory-safe and must NOT fire."""
        src = (
            "def load_checkpoint(path):\n"
            "    with open(path, 'rb') as f:\n"
            "        data = f.read()\n"
            "    return msgpack.unpackb(data, raw=False)\n"
        )
        findings = _scan(tmp_path, "no_hook.py", src, "TNT-DESER-007")
        assert findings == [], "a bare msgpack.unpackb() with no hook must not be flagged"

    def test_schema_validated_not_flagged(self, tmp_path):
        """A hookless decode whose result is schema-validated is safe."""
        src = (
            "def load_checkpoint(path, Model):\n"
            "    with open(path, 'rb') as f:\n"
            "        data = f.read()\n"
            "    raw = msgpack.unpackb(data, raw=False)\n"
            "    validated = Model.model_validate(raw)\n"
            "    return validated\n"
        )
        findings = _scan(tmp_path, "schema.py", src, "TNT-DESER-007")
        assert findings == [], "a schema-validated hookless decode must not be flagged"

    def test_pickle_fallback_not_flagged_here(self, tmp_path):
        """Acceptance (c): the msgpack-with-pickle-fallback shape has no hook, so
        TNT-DESER-007 stays silent -- it belongs to ns-aiml-041."""
        src = (
            "def load_checkpoint(path):\n"
            "    with open(path, 'rb') as f:\n"
            "        data = f.read()\n"
            "    try:\n"
            "        return msgpack.unpackb(data, raw=False)\n"
            "    except Exception:\n"
            "        return pickle.loads(data)\n"
        )
        findings = _scan(tmp_path, "pickle_fallback.py", src, "TNT-DESER-007")
        assert findings == [], (
            "the pickle-fallback shape (no hook) must not be flagged here; "
            "it belongs to ns-aiml-041"
        )

    def test_pickle_fallback_owned_by_ns_aiml_041(self, tmp_path):
        """Acceptance (c) control: the pickle-fallback shape IS caught by
        ns-aiml-041's broad msgpack regex, confirming the split is real."""
        src = (
            "def load_checkpoint(path):\n"
            "    with open(path, 'rb') as f:\n"
            "        data = f.read()\n"
            "    try:\n"
            "        return msgpack.unpackb(data, raw=False)\n"
            "    except Exception:\n"
            "        return pickle.loads(data)\n"
        )
        owned = _scan(
            tmp_path,
            "pickle_fallback_ns.py",
            src,
            "ns-aiml-041",
            rule_file="converted/ai_security.yaml",
        )
        assert owned, "the pickle-fallback shape must be owned by ns-aiml-041"

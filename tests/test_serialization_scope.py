"""Tests for SerializationScopePass (SER-SCOPE-001).

The motivating cases are both real: AutoGen's `FileSurfer` drops `base_path`
(its only directory confinement) and `TextMentionTermination` drops `sources`
(which scopes who may end a run) when serialized.
"""

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult, Severity
from rowan.passes.base import ScanContext
from rowan.passes.serialization_scope import SerializationScopePass


def _run(tmp_path: Path) -> list:
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return SerializationScopePass().run(context).findings


def test_detects_dropped_confinement_parameter(tmp_path):
    """A base_path the serializer never emits is a scope-widening round trip."""
    (tmp_path / "surfer.py").write_text(
        "class FileSurfer:\n"
        "    def __init__(self, name, base_path=None):\n"
        "        self.name = name\n"
        "        self._base_path = base_path\n"
        "\n"
        "    def _to_config(self):\n"
        "        return FileSurferConfig(name=self.name)\n"
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "SER-SCOPE-001"
    assert findings[0].metadata["dropped_parameter"] == "base_path"
    assert findings[0].severity == Severity.MEDIUM


def test_no_finding_when_parameter_is_emitted(tmp_path):
    """The parameter is renamed to an attribute but still emitted."""
    (tmp_path / "surfer.py").write_text(
        "class FileSurfer:\n"
        "    def __init__(self, name, base_path=None):\n"
        "        self._base_path = base_path\n"
        "\n"
        "    def _to_config(self):\n"
        "        return FileSurferConfig(name=self.name, base_path=self._base_path)\n"
    )
    assert _run(tmp_path) == []


def test_resources_does_not_match_sources_marker(tmp_path):
    """Regression: substring matching made `resources` hit the `sources` marker.

    That single bug produced 26 of 29 findings on kserve's generated models.
    """
    (tmp_path / "spec.py").write_text(
        "class PodSpec:\n"
        "    def __init__(self, name, resources=None):\n"
        "        self.resources = resources\n"
        "\n"
        "    def _to_config(self):\n"
        "        return Config(name=self.name)\n"
    )
    assert _run(tmp_path) == []


def test_reflective_serializer_is_skipped(tmp_path):
    """A serializer that enumerates attributes generically drops nothing."""
    (tmp_path / "model.py").write_text(
        "class Generated:\n"
        "    def __init__(self, name, allowed_hosts=None):\n"
        "        self.allowed_hosts = allowed_hosts\n"
        "\n"
        "    def to_dict(self):\n"
        "        result = {}\n"
        "        for attr, _ in self.openapi_types.items():\n"
        "            result[attr] = getattr(self, attr)\n"
        "        return result\n"
    )
    assert _run(tmp_path) == []


def test_class_without_serializer_is_ignored(tmp_path):
    """No serializer means no round trip and nothing to widen."""
    (tmp_path / "plain.py").write_text(
        "class Plain:\n"
        "    def __init__(self, base_path=None):\n"
        "        self._base_path = base_path\n"
    )
    assert _run(tmp_path) == []


def test_word_start_matching_accepts_underscore_prefix(tmp_path):
    """`allowed` must still match inside `extra_allowed_paths`."""
    (tmp_path / "thing.py").write_text(
        "class Thing:\n"
        "    def __init__(self, extra_allowed_paths=None):\n"
        "        self._paths = extra_allowed_paths\n"
        "\n"
        "    def to_dict(self):\n"
        "        return {'name': self.name}\n"
    )
    findings = _run(tmp_path)
    assert len(findings) == 1
    assert findings[0].metadata["dropped_parameter"] == "extra_allowed_paths"


def test_syntax_error_file_does_not_crash_the_pass(tmp_path):
    (tmp_path / "broken.py").write_text("class Broken:\n    def __init__(self\n")
    assert _run(tmp_path) == []

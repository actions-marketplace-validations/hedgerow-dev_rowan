from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.config_taint import ConfigTaintPass

_DECISION = """
def read_artifact(path):
    strict = runtime_settings.get_bool("security.strict_paths", True)
    if strict:
        path = sanitize_path(path)
    return registry.read_raw(path)
"""


def _scan(root: Path):
    return ConfigTaintPass().run(
        ScanContext(root, ScanConfig(root), ScanResult())
    ).findings


def test_request_deep_merge_controlling_security_gate_is_reported(tmp_path: Path) -> None:
    (tmp_path / "preferences.py").write_text(
        """
def save_preferences():
    data = request.get_json() or {}
    preferences = data.get("preferences", {})
    for namespace, patch in preferences.items():
        runtime_settings.merge_namespace(namespace, patch)
""",
        encoding="utf-8",
    )
    (tmp_path / "artifacts.py").write_text(_DECISION, encoding="utf-8")

    findings = _scan(tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "CONFIG-SECURITY-TAINT-001"
    assert finding.cwe_ids == [15]
    assert finding.metadata["security_key"] == "security.strict_paths"
    assert finding.taint_flow is not None


def test_namespace_allowlist_suppresses_user_preferences(tmp_path: Path) -> None:
    (tmp_path / "preferences.py").write_text(
        """
PREFERENCE_NAMESPACES = {"ui", "llm"}
def save_preferences():
    data = request.get_json() or {}
    preferences = data.get("preferences", {})
    for namespace, patch in preferences.items():
        if namespace not in PREFERENCE_NAMESPACES:
            continue
        runtime_settings.merge_namespace(namespace, patch)
""",
        encoding="utf-8",
    )
    (tmp_path / "artifacts.py").write_text(_DECISION, encoding="utf-8")
    assert _scan(tmp_path) == []


def test_literal_nonsecurity_namespace_does_not_arm_security_channel(tmp_path: Path) -> None:
    (tmp_path / "preferences.py").write_text(
        """
def save_theme():
    data = request.get_json() or {}
    runtime_settings.merge_namespace("ui", data.get("theme", {}))
""",
        encoding="utf-8",
    )
    (tmp_path / "artifacts.py").write_text(_DECISION, encoding="utf-8")
    assert _scan(tmp_path) == []


def test_different_config_stores_do_not_cross_contaminate(tmp_path: Path) -> None:
    (tmp_path / "preferences.py").write_text(
        """
def save_preferences():
    data = request.get_json() or {}
    preferences = data.get("preferences", {})
    for namespace, patch in preferences.items():
        user_settings.merge_namespace(namespace, patch)
""",
        encoding="utf-8",
    )
    (tmp_path / "artifacts.py").write_text(_DECISION, encoding="utf-8")
    assert _scan(tmp_path) == []

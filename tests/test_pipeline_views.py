"""The default (actionable) view must keep evidence-bearing MEDIUMs from
structural engines and reachable dependency CVEs (BACKLOG PL-01)."""

from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, Severity
from rowan.pipeline import ScanPipeline

_SURFER = (
    "class FileSurfer:\n"
    "    def __init__(self, name, base_path=None):\n"
    "        self.name = name\n"
    "        self._base_path = base_path\n"
    "\n"
    "    def _to_config(self):\n"
    "        return FileSurferConfig(name=self.name)\n"
)


def test_actionable_keeps_structural_engine_medium(tmp_path: Path):
    (tmp_path / "surfer.py").write_text(_SURFER, encoding="utf-8")
    config = ScanConfig(target=tmp_path, enable_sca=False, report_view="actionable")
    result = ScanPipeline(config).run()
    ser = [f for f in result.findings if f.rule_id == "SER-SCOPE-001"]
    assert len(ser) == 1, [f.rule_id for f in result.findings]
    assert ser[0].metadata.get("evidence_tier") == "engine"


def _cve(reachability: str | None) -> Finding:
    metadata = {"evidence_tier": "self-evident", "package": "requests"}
    if reachability:
        metadata["reachability"] = reachability
    return Finding(
        rule_id="CVE-2023-0001",
        message="known vuln",
        severity=Severity.MEDIUM,
        category=Category.SUPPLY_CHAIN,
        file_path="requirements.txt",
        start_line=1,
        engine="depguard",
        metadata=metadata,
    )


def test_actionable_keeps_reachable_medium_cve(tmp_path: Path):
    pipeline = ScanPipeline(ScanConfig(target=tmp_path))
    assert pipeline._in_actionable_view(_cve("reachable")) is True
    assert pipeline._in_actionable_view(_cve("unknown")) is False
    assert pipeline._in_actionable_view(_cve(None)) is False


def test_unset_engine_is_pattern_only():
    from rowan.passes.enrichment import _is_evidence_bearing_engine

    assert _is_evidence_bearing_engine("") is False
    assert _is_evidence_bearing_engine("opengrep") is False
    assert _is_evidence_bearing_engine("depguard") is False
    assert _is_evidence_bearing_engine("serialization-scope") is True

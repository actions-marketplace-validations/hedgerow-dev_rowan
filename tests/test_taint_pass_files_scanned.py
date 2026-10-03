"""TE-15: files_scanned is what Opengrep scanned, across languages."""

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.taint import TaintPass
from rowan.taint.opengrep_adapter import ScanOutcome


def test_files_scanned_is_opengrep_target_count(tmp_path, monkeypatch):
    for name in ("a.py", "b.py", "c.js", "d.js"):
        (tmp_path / name).write_text("x = 1\n")
    rules = Path(__file__).parent.parent / "rules"
    taint = TaintPass(rules_dir=rules)
    monkeypatch.setattr(taint._adapter, "is_installed", lambda: True)
    monkeypatch.setattr(taint._adapter, "scan_collect_with_rules",
                        lambda *a, **k: ScanOutcome(findings=[], status="ok", target_count=4))

    result = taint.run(ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult()))

    assert result.files_scanned == 4

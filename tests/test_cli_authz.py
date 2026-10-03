"""CLI wiring for the opt-in BOLA/IDOR pass (Phase 7 deployment hook)."""

from __future__ import annotations

from click.testing import CliRunner

from rowan import cli
from rowan.core.findings import ScanResult


def test_scan_authz_flag_sets_enable_authz(tmp_path, monkeypatch):
    captured = {}

    class FakePipeline:
        def __init__(self, config):
            captured["config"] = config

        def run(self):
            return ScanResult()

    monkeypatch.setattr(cli, "ScanPipeline", FakePipeline)
    result = CliRunner().invoke(cli.main, ["scan", str(tmp_path), "--authz"])
    assert result.exit_code == 0, result.output
    assert captured["config"].enable_authz is True

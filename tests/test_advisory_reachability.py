"""Integration: advisory-derived vulnerable functions feeding SCA reachability.

Proves the long-tail reachability path end-to-end through
``SCAPass._apply_reachability`` -- including the load-bearing safety property
that an advisory naming no in-namespace symbol produces *no* downgrade.
"""

from __future__ import annotations

from pathlib import Path

from rowan.core.findings import Category, Finding, Severity
from rowan.passes.sca import SCAPass


def _finding(package, details, cve="CVE-2099-0001"):
    return Finding(
        rule_id=f"SCA-{cve}", message=f"CVE in {package}", severity=Severity.HIGH,
        category=Category.SUPPLY_CHAIN, file_path="", start_line=0, confidence=0.8,
        engine="depguard", metadata={"cve_id": cve, "package": package, "ecosystem": "PyPI", "details": details},
    )


def _write(root: Path, body: str) -> None:
    (root / "app.py").write_text(body, encoding="utf-8")


class TestAdvisoryDerivedReachability:
    def test_reachable_when_advisory_symbol_is_called(self, tmp_path):
        _write(tmp_path, "import fakepkg\nfakepkg.danger('x')\n")
        f = _finding("fakepkg", "Vulnerable in `fakepkg.danger()`.")
        SCAPass()._apply_reachability([f], tmp_path)
        assert f.metadata["reachability"] == "reachable"
        assert f.metadata["vuln_func_source"] == "advisory"
        assert f.metadata["reachability_evidence"] == "fakepkg.danger"
        assert f.metadata["vulnerable_symbols"] == ["fakepkg.danger"]
        assert f.severity == Severity.HIGH  # reachable -> not downgraded

    def test_unreachable_when_advisory_symbol_not_called(self, tmp_path):
        _write(tmp_path, "import fakepkg\nfakepkg.safe('x')\n")
        f = _finding("fakepkg", "Vulnerable in `fakepkg.danger()`.")
        SCAPass()._apply_reachability([f], tmp_path)
        assert f.metadata["reachability"] == "unknown"
        assert f.metadata["vuln_func_source"] == "advisory"
        assert f.severity == Severity.HIGH  # absence is indeterminate
        assert f.confidence == 0.8
        assert f.metadata["vulnerable_symbols"] == ["fakepkg.danger"]

    def test_no_downgrade_when_advisory_names_no_in_namespace_symbol(self, tmp_path):
        # Safety: advisory only mentions os.system (impact, not the package's
        # own API) -> nothing extracted -> full severity preserved.
        _write(tmp_path, "import fakepkg\nfakepkg.safe('x')\n")
        f = _finding("fakepkg", "Leads to RCE via `os.system(payload)`.")
        SCAPass()._apply_reachability([f], tmp_path)
        assert "reachability" not in f.metadata
        assert f.severity == Severity.HIGH

    def test_unreachable_when_package_never_imported(self, tmp_path):
        # The primary win: a (e.g. transitive) package whose advisory names a
        # symbol, but which the code never imports or calls at all, downgrades.
        _write(tmp_path, "import something_else\nsomething_else.run()\n")
        f = _finding("fakepkg", "Vulnerable in `fakepkg.Client.fetch()`.")
        SCAPass()._apply_reachability([f], tmp_path)
        assert f.metadata["reachability"] == "unknown"
        assert f.severity == Severity.HIGH

    def test_curated_map_takes_precedence(self, tmp_path):
        _write(tmp_path, "import torch\ntorch.load('m.pt')\n")
        # details would also extract, but the curated map must win.
        f = _finding("torch", "see `torch.load`")
        SCAPass()._apply_reachability([f], tmp_path)
        assert f.metadata["reachability"] == "reachable"
        assert f.metadata["vuln_func_source"] == "curated"

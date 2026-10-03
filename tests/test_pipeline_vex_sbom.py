"""End-to-end pipeline wiring for VEX/SBOM output.

The load-bearing property: VEX and SBOM are emitted from the *complete*
dependency inventory, before the severity/baseline/ignore filters prune the
findings list. A `--severity high` run must still record every
`not_affected` (LOW, unreachable) VEX statement -- that suppression signal is
the entire point of VEX and must survive the filter.
"""

from __future__ import annotations

import json

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.pipeline import ScanPipeline


class _FakeSCAPass:
    """Stand-in for SCAPass: injects one LOW unreachable dependency CVE plus
    a component inventory, with no network or opengrep."""

    name = "sca"

    def run(self, context):
        result = ScanResult()
        result.add_finding(
            Finding(
                rule_id="SCA-CVE-2023-9999",
                message="CVE in requests",
                severity=Severity.LOW,  # unreachable CVEs are downgraded to LOW
                category=Category.SUPPLY_CHAIN,
                file_path="",
                start_line=0,
                confidence=0.3,
                engine="depguard",
                metadata={
                    "cve_id": "CVE-2023-9999",
                    "package": "requests",
                    "version": "2.28.0",
                    "ecosystem": "PyPI",
                    "reachability": "unreachable",
                },
            )
        )
        result.metadata["dependencies"] = [
            {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI", "direct": True},
        ]
        return result


def test_vex_and_sbom_survive_severity_filter(tmp_path, monkeypatch):
    monkeypatch.setattr("rowan.scan_plan.SCAPass", lambda: _FakeSCAPass())
    # Discovery skips the SCA pass entirely when the inventory has no
    # dependency manifest, so give the fake pass something to be applicable to.
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")

    vex_path = tmp_path / "vex.json"
    sbom_path = tmp_path / "sbom.json"
    config = ScanConfig(
        target=tmp_path,
        # Keep the pipeline fully offline: legacy regex engine (no opengrep),
        # no taint/cross-file passes.
        no_taint=True,
        no_cross_file=True,
        legacy_neuroscan=True,
        severity=Severity.HIGH,  # would strip the LOW finding from the report
        vex_path=vex_path,
        sbom_path=sbom_path,
    )

    result = ScanPipeline(config).run()

    # The LOW finding is filtered out of the findings report by --severity high...
    assert all(f.rule_id != "SCA-CVE-2023-9999" for f in result.findings)

    # ...but the VEX document still records it as not_affected.
    vex = json.loads(vex_path.read_text())
    assert len(vex["statements"]) == 1
    stmt = vex["statements"][0]
    assert stmt["vulnerability"]["name"] == "CVE-2023-9999"
    assert stmt["status"] == "not_affected"
    assert stmt["justification"] == "vulnerable_code_not_in_execute_path"

    # ...and the SBOM lists the component.
    sbom = json.loads(sbom_path.read_text())
    assert sbom["bomFormat"] == "CycloneDX"
    names = {c["name"] for c in sbom["components"]}
    assert "requests" in names


def test_sbom_preserves_dependency_chain_and_graph_edges():
    from rowan.reporters import to_cyclonedx

    result = ScanResult()
    result.metadata["dependencies"] = [
        {"name": "requests", "version": "2.31.0", "ecosystem": "PyPI", "direct": True},
        {
            "name": "urllib3",
            "version": "2.0.7",
            "ecosystem": "PyPI",
            "direct": False,
            "dependency_chain": ["requests", "urllib3"],
        },
    ]

    sbom = to_cyclonedx(result, timestamp="2026-01-01T00:00:00+00:00")
    urllib3 = next(c for c in sbom["components"] if c["name"] == "urllib3")
    assert {p["name"] for p in urllib3["properties"]} == {"rowan:dependency-chain"}
    assert sbom["dependencies"] == [
        {
            "ref": urllib3["bom-ref"],
            "dependsOn": [next(c["bom-ref"] for c in sbom["components"] if c["name"] == "requests")],
        }
    ]


class _DegradedSCAPass(_FakeSCAPass):
    """OSV unreachable: the inventory is known, the vulnerability data is not."""

    def run(self, context):
        result = ScanResult()
        result.metadata["dependencies"] = [
            {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI", "direct": True},
        ]
        result.degraded_passes["sca"] = "OSV down"
        return result


def test_vex_not_written_when_sca_degraded(tmp_path, monkeypatch):
    """PL-04: an empty VEX from a failed OSV lookup reads as 'no known
    vulnerabilities'; it must not be written, and the SBOM must say why."""
    monkeypatch.setattr("rowan.scan_plan.SCAPass", lambda: _DegradedSCAPass())
    (tmp_path / "requirements.txt").write_text("requests==2.28.0\n", encoding="utf-8")
    vex_path = tmp_path / "vex.json"
    vex_path.write_text("{}", encoding="utf-8")  # a stale VEX from an earlier run
    sbom_path = tmp_path / "sbom.json"

    result = ScanPipeline(ScanConfig(
        target=tmp_path, no_taint=True, no_cross_file=True, legacy_neuroscan=True,
        vex_path=vex_path, sbom_path=sbom_path,
    )).run()

    assert not vex_path.exists()
    assert any("VEX" in e and "OSV down" in e for e in result.errors)
    sbom = json.loads(sbom_path.read_text())
    assert {"name": "rowan:degraded", "value": "OSV down"} in sbom["metadata"]["properties"]

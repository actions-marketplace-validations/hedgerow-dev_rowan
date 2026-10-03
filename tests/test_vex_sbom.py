"""Tests for supply-chain artifact reporters: OpenVEX and CycloneDX SBOM.

VEX status is driven by the SCA reachability signal; the SBOM is the full
declared dependency inventory. Both must produce valid, standard-shaped
documents and use correct Package URLs.
"""

from __future__ import annotations

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.reporters import _finding_to_purl, _purl, to_cyclonedx, to_vex

TS = "2026-07-19T00:00:00+00:00"


def _sca_finding(cve, pkg, version, ecosystem="PyPI", reachability=None, evidence=None):
    metadata = {
        "cve_id": cve,
        "package": pkg,
        "version": version,
        "ecosystem": ecosystem,
    }
    if reachability is not None:
        metadata["reachability"] = reachability
    if evidence is not None:
        metadata["reachability_evidence"] = evidence
    return Finding(
        rule_id=f"SCA-{cve}",
        message=f"CVE in {pkg}",
        severity=Severity.HIGH,
        category=Category.SUPPLY_CHAIN,
        file_path="",
        start_line=0,
        engine="depguard",
        metadata=metadata,
    )


class TestPurl:
    def test_pypi(self):
        assert _purl("PyPI", "requests", "2.28.0") == "pkg:pypi/requests@2.28.0"

    def test_npm(self):
        assert _purl("npm", "lodash", "4.17.20") == "pkg:npm/lodash@4.17.20"

    def test_maven_group_artifact_split(self):
        assert (
            _purl("Maven", "org.apache.commons:commons-text", "1.9")
            == "pkg:maven/org.apache.commons/commons-text@1.9"
        )

    def test_go_and_cargo_and_gem_and_composer(self):
        assert _purl("Go", "golang.org/x/net", "0.1.0") == "pkg:golang/golang.org/x/net@0.1.0"
        assert _purl("crates.io", "regex", "1.5.0") == "pkg:cargo/regex@1.5.0"
        assert _purl("RubyGems", "rails", "7.0.0") == "pkg:gem/rails@7.0.0"
        assert _purl("Packagist", "monolog/monolog", "2.0") == "pkg:composer/monolog/monolog@2.0"

    def test_wildcard_version_omitted(self):
        assert _purl("PyPI", "requests", "*") == "pkg:pypi/requests"

    def test_unknown_ecosystem_returns_none(self):
        assert _purl("cocoapods", "AFNetworking", "1.0") is None

    def test_finding_wrapper(self):
        f = _sca_finding("CVE-2023-1", "requests", "2.28.0")
        assert _finding_to_purl(f) == "pkg:pypi/requests@2.28.0"


class TestToVex:
    def test_unreachable_becomes_not_affected_with_justification(self):
        result = ScanResult(findings=[
            _sca_finding("CVE-2023-1", "requests", "2.28.0", reachability="unreachable"),
        ])
        doc = to_vex(result, timestamp=TS)
        assert doc["@context"] == "https://openvex.dev/ns/v0.2.0"
        assert doc["timestamp"] == TS
        assert len(doc["statements"]) == 1
        stmt = doc["statements"][0]
        assert stmt["vulnerability"]["name"] == "CVE-2023-1"
        assert stmt["products"] == [{"@id": "pkg:pypi/requests@2.28.0"}]
        assert stmt["status"] == "not_affected"
        assert stmt["justification"] == "vulnerable_code_not_in_execute_path"

    def test_reachable_becomes_affected_with_action(self):
        result = ScanResult(findings=[
            _sca_finding(
                "CVE-2023-2", "torch", "1.10.0",
                reachability="reachable", evidence="torch.load",
            ),
        ])
        stmt = to_vex(result, timestamp=TS)["statements"][0]
        assert stmt["status"] == "affected"
        assert "torch.load" in stmt["action_statement"]

    def test_no_reachability_determination_is_under_investigation(self):
        result = ScanResult(findings=[
            _sca_finding("CVE-2023-3", "somepkg", "1.0.0"),  # no reachability key
        ])
        stmt = to_vex(result, timestamp=TS)["statements"][0]
        assert stmt["status"] == "under_investigation"

    def test_phantom_and_code_findings_excluded(self):
        phantom = Finding(
            rule_id="SCA-PHANTOM-001", message="Phantom", severity=Severity.INFO,
            category=Category.SUPPLY_CHAIN, file_path="", start_line=0, engine="depguard",
            metadata={"phantom_dependency": True, "package": "requests", "ecosystem": "PyPI"},
        )
        code = Finding(
            rule_id="NS-DESER-001", message="pickle", severity=Severity.CRITICAL,
            category=Category.DESERIALIZATION, file_path="a.py", start_line=1, engine="neuroscan",
        )
        result = ScanResult(findings=[
            phantom, code,
            _sca_finding("CVE-2023-4", "flask", "2.0.0", reachability="unreachable"),
        ])
        doc = to_vex(result, timestamp=TS)
        # Only the real CVE finding produces a statement.
        assert len(doc["statements"]) == 1
        assert doc["statements"][0]["vulnerability"]["name"] == "CVE-2023-4"

    def test_id_is_content_stable(self):
        result = ScanResult(findings=[
            _sca_finding("CVE-2023-5", "requests", "2.28.0", reachability="unreachable"),
        ])
        a = to_vex(result, timestamp=TS)["@id"]
        b = to_vex(result, timestamp="2099-01-01T00:00:00+00:00")["@id"]
        # @id derives from statement content, not the timestamp.
        assert a == b


class TestToCycloneDX:
    def _result_with_inventory(self):
        result = ScanResult()
        result.metadata["dependencies"] = [
            {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI", "direct": True,
             "source_files": ["requirements.txt"]},
            {"name": "urllib3", "version": "1.26.5", "ecosystem": "PyPI", "direct": False},
            {"name": "org.apache.commons:commons-text", "version": "1.9", "ecosystem": "Maven", "direct": True},
        ]
        return result

    def test_bom_shape_and_components(self):
        doc = to_cyclonedx(self._result_with_inventory(), timestamp=TS)
        assert doc["bomFormat"] == "CycloneDX"
        assert doc["specVersion"] == "1.5"
        assert doc["serialNumber"].startswith("urn:uuid:")
        assert doc["metadata"]["timestamp"] == TS
        assert len(doc["components"]) == 3

    def test_component_purls(self):
        doc = to_cyclonedx(self._result_with_inventory(), timestamp=TS)
        purls = {c["name"]: c.get("purl") for c in doc["components"]}
        assert purls["requests"] == "pkg:pypi/requests@2.28.0"
        assert purls["urllib3"] == "pkg:pypi/urllib3@1.26.5"
        assert purls["org.apache.commons:commons-text"] == "pkg:maven/org.apache.commons/commons-text@1.9"
        requests = next(c for c in doc["components"] if c["name"] == "requests")
        assert requests["properties"] == [
            {"name": "rowan:source-file", "value": "requirements.txt"}
        ]

    def test_bom_refs_unique(self):
        result = ScanResult()
        # Two identical purls (e.g. same package resolved in two dep files)
        # must not collide on bom-ref.
        result.metadata["dependencies"] = [
            {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI", "direct": True},
            {"name": "requests", "version": "2.28.0", "ecosystem": "PyPI", "direct": True},
        ]
        doc = to_cyclonedx(result, timestamp=TS)
        refs = [c["bom-ref"] for c in doc["components"]]
        assert len(refs) == len(set(refs))

    def test_empty_inventory_is_valid_empty_bom(self):
        doc = to_cyclonedx(ScanResult(), timestamp=TS)
        assert doc["components"] == []
        assert doc["bomFormat"] == "CycloneDX"

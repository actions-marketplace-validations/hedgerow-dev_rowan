"""Tests for EPSS (exploit-probability) enrichment of SCA findings.

EPSS is best-effort: it enriches dependency CVE findings with FIRST.org's
exploit-probability score, keyed on the CVE id (falling back to a CVE alias
when OSV's primary id is a GHSA). A lookup failure must never crash or mark
the scan degraded.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from rowan.core.findings import Category, Finding, Severity
from rowan.passes.sca import SCAPass


def _sca_finding(cve_id, aliases=None, engine="depguard"):
    md = {"cve_id": cve_id, "package": "requests", "version": "2.28.0", "ecosystem": "PyPI"}
    if aliases:
        md["aliases"] = aliases
    return Finding(
        rule_id=f"SCA-{cve_id}", message="CVE", severity=Severity.HIGH,
        category=Category.SUPPLY_CHAIN, file_path="", start_line=0,
        engine=engine, metadata=md,
    )


def _epss_response(rows):
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"status": "OK", "data": rows}
    return resp


class TestApplyEpss:
    def test_score_attached_by_cve_id(self):
        f = _sca_finding("CVE-2021-1234")
        resp = _epss_response([{"cve": "CVE-2021-1234", "epss": "0.94", "percentile": "0.99"}])
        with patch("httpx.get", return_value=resp) as mock_get:
            SCAPass()._apply_epss([f])
        assert f.metadata["epss"] == 0.94
        assert f.metadata["epss_percentile"] == 0.99
        # queried with the CVE id
        assert "CVE-2021-1234" in mock_get.call_args.kwargs["params"]["cve"]

    def test_ghsa_primary_id_uses_cve_alias(self):
        f = _sca_finding("GHSA-xxxx-yyyy-zzzz", aliases=["CVE-2022-5555"])
        resp = _epss_response([{"cve": "CVE-2022-5555", "epss": "0.5", "percentile": "0.8"}])
        with patch("httpx.get", return_value=resp) as mock_get:
            SCAPass()._apply_epss([f])
        assert f.metadata["epss"] == 0.5
        assert "CVE-2022-5555" in mock_get.call_args.kwargs["params"]["cve"]

    def test_no_cve_id_is_skipped_without_network_call(self):
        f = _sca_finding("PYSEC-2021-1", aliases=["GHSA-aaaa-bbbb-cccc"])
        with patch("httpx.get") as mock_get:
            SCAPass()._apply_epss([f])
        mock_get.assert_not_called()
        assert "epss" not in f.metadata

    def test_network_error_is_silent_no_crash(self):
        import httpx

        f = _sca_finding("CVE-2021-1234")
        with patch("httpx.get", side_effect=httpx.ConnectError("boom")):
            SCAPass()._apply_epss([f])  # must not raise
        assert "epss" not in f.metadata

    def test_non_sca_findings_ignored(self):
        code = Finding(
            rule_id="NS-DESER-001", message="pickle", severity=Severity.CRITICAL,
            category=Category.DESERIALIZATION, file_path="a.py", start_line=1,
            engine="neuroscan", metadata={"cve_id": "CVE-2021-1234"},
        )
        with patch("httpx.get") as mock_get:
            SCAPass()._apply_epss([code])
        mock_get.assert_not_called()

    def test_missing_score_in_response_leaves_finding_unenriched(self):
        f = _sca_finding("CVE-2021-1234")
        resp = _epss_response([])  # EPSS has no data for this CVE
        with patch("httpx.get", return_value=resp):
            SCAPass()._apply_epss([f])
        assert "epss" not in f.metadata

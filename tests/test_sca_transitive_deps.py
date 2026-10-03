"""Tests for GitHub issue #80: SCA transitive dependency resolution +
version-range CVE matching.

Two gaps in the previous SCA pass: (1) only direct/declared dependencies
were labeled -- lockfiles' own resolved graphs already list transitive
packages, but nothing distinguished them or recorded the path from a direct
dependency down to the vulnerable one; (2) a manifest-only range spec
(">=1.0", "^2.0.0") was sent to OSV's querybatch verbatim as `version`, which
expects an exact pin to check against affected ranges, not a range to solve
itself -- so range specs were silently mismatched instead of resolved or
flagged as indeterminate.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from rowan.passes.sca import SCAPass


def _write(tmp_path, name: str, content: str):
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestPoetryLockChainAttribution:
    def test_transitive_package_gets_chain_via_direct_dependency(self, tmp_path):
        _write(tmp_path, "pyproject.toml", (
            "[tool.poetry.dependencies]\n"
            'python = "^3.10"\n'
            'requests = "^2.28.0"\n'
        ))
        _write(tmp_path, "poetry.lock", (
            '[[package]]\nname = "requests"\nversion = "2.28.0"\n'
            "[package.dependencies]\n"
            'urllib3 = ">=1.21.1,<3"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "1.26.5"\n'
        ))
        pkgs = SCAPass()._extract_packages(tmp_path / "poetry.lock")
        by_name = {pk["name"]: pk for pk in pkgs}

        assert by_name["requests"]["direct"] is True
        assert by_name["requests"]["chain"] == ["requests"]

        assert by_name["urllib3"]["direct"] is False
        assert by_name["urllib3"]["chain"] == ["requests", "urllib3"]

    def test_no_companion_manifest_defaults_everything_direct(self, tmp_path):
        """Best-effort per issue #80: without a manifest to cross-reference,
        don't guess at transitivity -- treat every package as direct rather
        than mislabeling something we can't actually determine."""
        _write(tmp_path, "poetry.lock", (
            '[[package]]\nname = "requests"\nversion = "2.28.0"\n'
        ))
        pkgs = SCAPass()._extract_packages(tmp_path / "poetry.lock")
        assert pkgs[0]["direct"] is True
        assert pkgs[0]["chain"] is None


class TestNpmLockChainFromInstallPath:
    def test_transitive_package_chain_derived_from_nesting_path(self, tmp_path):
        data = {
            "packages": {
                "": {},
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/express/node_modules/qs": {"version": "6.5.0"},
            }
        }
        _write(tmp_path, "package-lock.json", json.dumps(data))
        pkgs = SCAPass()._extract_packages(tmp_path / "package-lock.json")
        by_name = {pk["name"]: pk for pk in pkgs}

        assert by_name["express"]["direct"] is True
        assert by_name["express"]["chain"] == ["express"]

        assert by_name["qs"]["direct"] is False
        assert by_name["qs"]["chain"] == ["express", "qs"]

    def test_hoisted_transitive_package_uses_root_dependencies(self, tmp_path):
        data = {
            "packages": {
                "": {"dependencies": {"express": "4.18.0"}},
                "node_modules/express": {"version": "4.18.0"},
                "node_modules/qs": {"version": "6.5.0"},
            }
        }
        _write(tmp_path, "package-lock.json", json.dumps(data))
        by_name = {p["name"]: p for p in SCAPass()._extract_packages(tmp_path / "package-lock.json")}
        assert by_name["express"]["direct"] is True
        assert by_name["qs"]["direct"] is False


class TestAcceptanceCleanDirectVulnerableTransitive:
    """Issue #80's acceptance criterion: a project with a clean direct
    dependency but a vulnerable transitive dependency must report the CVE,
    labeled transitive, with the dependency chain."""

    def test_transitive_cve_reported_with_chain(self, tmp_path):
        _write(tmp_path, "pyproject.toml", (
            "[tool.poetry.dependencies]\n"
            'python = "^3.10"\n'
            'requests = "^2.28.0"\n'
        ))
        _write(tmp_path, "poetry.lock", (
            '[[package]]\nname = "requests"\nversion = "2.28.0"\n'
            "[package.dependencies]\n"
            'urllib3 = ">=1.21.1,<3"\n\n'
            '[[package]]\nname = "urllib3"\nversion = "1.26.5"\n'
        ))
        sca = SCAPass()
        packages = sca._extract_packages(tmp_path / "poetry.lock")

        def fake_post(url, json, timeout):
            results = []
            for q in json["queries"]:
                if q["package"]["name"] == "urllib3":
                    results.append({"vulns": [{"id": "GHSA-urllib3", "summary": "CRLF injection"}]})
                else:
                    results.append({"vulns": []})
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"results": results}
            return resp

        with patch("httpx.post", side_effect=fake_post):
            findings, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert len(findings) == 1
        f = findings[0]
        assert f.metadata["package"] == "urllib3"
        assert f.metadata["direct"] is False
        assert f.metadata["dependency_chain"] == ["requests", "urllib3"]


class TestVersionRangeMatching:
    """Manifest-only range specs (no lockfile pin) must be resolved against
    OSV's affected ranges rather than sent verbatim as an exact version."""

    def _vuln_response(self, fixed: str):
        return {
            "results": [{
                "vulns": [{
                    "id": "GHSA-test",
                    "summary": "test vuln",
                    "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                        {"introduced": "0"}, {"fixed": fixed},
                    ]}]}],
                }],
            }],
        }

    def test_pip_range_spec_overlapping_vulnerable_range_is_reported(self):
        sca = SCAPass()
        packages = [{"name": "django", "version": ">=1.0,<2.0", "ecosystem": "PyPI"}]

        captured = {}

        def fake_post(url, json, timeout):
            captured["query"] = json
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = self._vuln_response(fixed="1.5.0")
            return resp

        with patch("httpx.post", side_effect=fake_post):
            findings, dropped = sca._check_vulnerabilities(packages)

        # No exact version sent -- OSV can't solve a range, only check one.
        assert "version" not in captured["query"]["queries"][0]
        assert dropped == 0
        assert len(findings) == 1
        assert findings[0].metadata.get("version_indeterminate") is not True

    def test_pip_range_spec_entirely_above_fixed_version_is_not_reported(self):
        """>=2.0 can never select a version below the 1.5.0 fix -- no overlap."""
        sca = SCAPass()
        packages = [{"name": "django", "version": ">=2.0", "ecosystem": "PyPI"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = self._vuln_response(fixed="1.5.0")
            return resp

        with patch("httpx.post", side_effect=fake_post):
            findings, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert findings == []

    def test_npm_caret_range_overlapping_vulnerable_range_is_reported(self):
        sca = SCAPass()
        packages = [{"name": "lodash", "version": "^3.0.0", "ecosystem": "npm"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = self._vuln_response(fixed="4.0.0")
            return resp

        with patch("httpx.post", side_effect=fake_post):
            findings, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert len(findings) == 1

    def test_npm_caret_range_above_fixed_version_is_not_reported(self):
        sca = SCAPass()
        packages = [{"name": "lodash", "version": "^5.0.0", "ecosystem": "npm"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = self._vuln_response(fixed="4.0.0")
            return resp

        with patch("httpx.post", side_effect=fake_post):
            findings, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert findings == []

    def test_unparseable_range_is_kept_and_flagged_indeterminate(self):
        """An OR-combined npm range ("||") isn't solved by this module --
        must not silently drop a possible vulnerability; keep it, flagged."""
        sca = SCAPass()
        packages = [{"name": "lodash", "version": "^3.0.0 || ^4.5.0", "ecosystem": "npm"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = self._vuln_response(fixed="4.0.0")
            return resp

        with patch("httpx.post", side_effect=fake_post):
            findings, dropped = sca._check_vulnerabilities(packages)

        assert dropped == 0
        assert len(findings) == 1
        assert findings[0].metadata["version_indeterminate"] is True
        assert findings[0].confidence < 0.8

    def test_exact_pinned_version_still_sent_directly_to_osv(self):
        """A lockfile-resolved exact version must still be queried the old
        way (version field sent directly) -- no behavior change there."""
        sca = SCAPass()
        packages = [{"name": "django", "version": "1.2.3", "ecosystem": "PyPI"}]

        captured = {}

        def fake_post(url, json, timeout):
            captured["query"] = json
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"results": [{"vulns": []}]}
            return resp

        with patch("httpx.post", side_effect=fake_post):
            sca._check_vulnerabilities(packages)

        assert captured["query"]["queries"][0]["version"] == "1.2.3"


class TestVulnHydration:
    """OSV querybatch returns only {id, modified} per vuln; the rich fields
    (summary/affected/aliases/severity) must be fetched per-id from
    /v1/vulns/{id}. Without this, severity, range-filtering, EPSS aliasing,
    nearest-fix, and advisory reachability all silently no-op on real scans."""

    def test_thin_querybatch_entry_is_hydrated(self):
        sca = SCAPass()
        packages = [{"name": "django", "version": "2.0.0", "ecosystem": "PyPI"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            # thin: only id + modified, exactly like the real endpoint
            resp.json.return_value = {"results": [{"vulns": [
                {"id": "GHSA-thin-1234", "modified": "2024-01-01T00:00:00Z"},
            ]}]}
            return resp

        def fake_get(url, timeout):
            assert url.endswith("/GHSA-thin-1234")  # hydration hit the vuln endpoint
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {
                "id": "GHSA-thin-1234",
                "summary": "SQL injection in django",
                "aliases": ["CVE-2099-0001"],
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": "2.5.0"},
                ]}]}],
                "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
            }
            return resp

        with patch("httpx.post", side_effect=fake_post), patch("httpx.get", side_effect=fake_get):
            findings, _ = sca._check_vulnerabilities(packages)

        assert len(findings) == 1
        f = findings[0]
        # rich fields from the hydrated record flowed through:
        assert "SQL injection" in f.message
        assert f.metadata["aliases"] == ["CVE-2099-0001"]
        assert f.metadata["fixed_version"] == "2.5.0"          # from affected.fixed
        assert f.severity.value == "critical"                   # from the CVSS vector

    def test_hydration_failure_falls_back_to_minimal_entry(self):
        sca = SCAPass()
        packages = [{"name": "django", "version": "2.0.0", "ecosystem": "PyPI"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"results": [{"vulns": [
                {"id": "GHSA-fail-1", "modified": "2024-01-01T00:00:00Z"},
            ]}]}
            return resp

        import httpx

        # hydration 404s -> finding still emitted from the minimal entry
        with patch("httpx.post", side_effect=fake_post), \
             patch("httpx.get", side_effect=httpx.HTTPError("404")):
            findings, _ = sca._check_vulnerabilities(packages)
        assert len(findings) == 1
        assert findings[0].metadata["cve_id"] == "GHSA-fail-1"

    def test_hydration_failure_is_marked_on_retained_finding(self):
        sca = SCAPass()
        packages = [{"name": "django", "version": "2.0.0", "ecosystem": "PyPI"}]

        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"results": [{"vulns": [{"id": "GHSA-fail-mark", "modified": "2024-01-01"}]}]}
            return resp

        import httpx

        with patch("httpx.post", side_effect=fake_post), patch("httpx.get", side_effect=httpx.HTTPError("503")):
            findings, _ = sca._check_vulnerabilities(packages)

        assert len(findings) == 1
        assert findings[0].metadata["advisory_hydration_failed"] is True
        assert sca._hydration_failures == {"GHSA-fail-mark"}


class TestRemediationFixVersion:
    """Each SCA finding should surface the nearest safe version to upgrade to,
    extracted from OSV's own `fixed` events -- the actionable 'upgrade to X'
    signal commercial SCA tools provide."""

    def _fake_post(self, fixed: str):
        def fake_post(url, json, timeout):
            resp = MagicMock()
            resp.raise_for_status.return_value = None
            resp.json.return_value = {"results": [{"vulns": [{
                "id": "GHSA-fix", "summary": "vuln",
                "affected": [{"ranges": [{"type": "ECOSYSTEM", "events": [
                    {"introduced": "0"}, {"fixed": fixed},
                ]}]}],
            }]}]}
            return resp
        return fake_post

    def test_fix_version_in_metadata_and_message(self):
        sca = SCAPass()
        packages = [{"name": "django", "version": "1.2.3", "ecosystem": "PyPI"}]
        with patch("httpx.post", side_effect=self._fake_post("1.5.0")):
            findings, _ = sca._check_vulnerabilities(packages)
        assert len(findings) == 1
        assert findings[0].metadata["fixed_version"] == "1.5.0"
        assert "upgrade to >= 1.5.0" in findings[0].message

    def test_no_fix_version_when_current_already_patched(self):
        sca = SCAPass()
        packages = [{"name": "django", "version": "1.5.0", "ecosystem": "PyPI"}]
        # OSV would not normally return a vuln for a patched exact version,
        # but if it does, we must not advise a downgrade/no-op upgrade.
        with patch("httpx.post", side_effect=self._fake_post("1.5.0")):
            findings, _ = sca._check_vulnerabilities(packages)
        assert len(findings) == 1
        assert "fixed_version" not in findings[0].metadata
        assert "upgrade to" not in findings[0].message

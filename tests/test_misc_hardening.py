"""Regression tests for a batch of low-severity fixes from the full codebase review:

- core/rules.py: a malformed regex pattern in a rule YAML used to be silently
  dropped (bare `except re.error: continue`), with no diagnostic trail --
  now logs a warning naming the rule and the bad pattern.
- reporters.py: to_json() hardcoded "version": "0.1.0" instead of the actual
  package version.
- ignore.py: a `path:` prefix match (e.g. "app") matched unrelated
  similarly-named paths (e.g. "app2/utils.py") with no separator boundary.
- taint/opengrep_adapter.py: a "--" argument terminator now precedes target
  paths in the Opengrep subprocess invocation.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

from rowan import __version__
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.rules import load_neuroscan_rules
from rowan.ignore import _is_ignored
from rowan.reporters import to_json
from rowan.taint.opengrep_adapter import OpengrepAdapter


class TestRuleLoadLogsInvalidPattern:
    def test_invalid_pattern_logs_warning_and_is_skipped(self, tmp_path, caplog):
        rule_yaml = tmp_path / "rule.yaml"
        rule_yaml.write_text(
            "rules:\n"
            "  - id: NS-BAD-001\n"
            "    name: test\n"
            "    severity: high\n"
            "    category: injection\n"
            "    cwe: [94]\n"
            "    languages: [python]\n"
            "    patterns:\n"
            "      - '(unclosed['\n"
            "      - 'eval\\('\n"
            "    message: test\n"
        )
        with caplog.at_level(logging.WARNING):
            rules = load_neuroscan_rules(rule_yaml)

        assert rules
        # The valid pattern still loaded; only the malformed one was dropped.
        assert len(rules[0].patterns) == 1
        assert any("NS-BAD-001" in r.message and "invalid pattern" in r.message for r in caplog.records)

    def test_invalid_sanitizer_pattern_logs_warning(self, tmp_path, caplog):
        rule_yaml = tmp_path / "rule.yaml"
        rule_yaml.write_text(
            "rules:\n"
            "  - id: NS-BAD-002\n"
            "    name: test\n"
            "    severity: high\n"
            "    category: injection\n"
            "    cwe: [94]\n"
            "    languages: [python]\n"
            "    patterns:\n"
            "      - 'eval\\('\n"
            "    sanitizers:\n"
            "      - '(unclosed['\n"
            "    message: test\n"
        )
        with caplog.at_level(logging.WARNING):
            rules = load_neuroscan_rules(rule_yaml)

        assert rules
        assert not rules[0].sanitizer_patterns
        assert any("NS-BAD-002" in r.message and "sanitizer" in r.message for r in caplog.records)


class TestJsonReportVersion:
    def test_to_json_uses_package_version(self):
        result = ScanResult()
        payload = to_json(result)
        import json
        data = json.loads(payload)
        assert data["version"] == __version__
        assert data["version"] != "0.1.0"


class TestIgnorePathBoundary:
    def _finding(self, path):
        return Finding(
            rule_id="NS-TEST", message="test", severity=Severity.HIGH,
            category=Category.INJECTION, file_path=path, start_line=1,
        )

    def test_prefix_does_not_match_unrelated_similarly_named_path(self, tmp_path):
        entries = [{"rule_id": "NS-TEST", "path": "app", "reason": "x"}]
        finding = self._finding(str(tmp_path / "app2" / "utils.py"))
        assert _is_ignored(finding, entries, {}, tmp_path) is False

    def test_prefix_matches_real_subdirectory(self, tmp_path):
        entries = [{"rule_id": "NS-TEST", "path": "app", "reason": "x"}]
        finding = self._finding(str(tmp_path / "app" / "utils.py"))
        assert _is_ignored(finding, entries, {}, tmp_path) is True

    def test_exact_file_match_still_works(self, tmp_path):
        entries = [{"rule_id": "NS-TEST", "path": "app.py", "reason": "x"}]
        finding = self._finding(str(tmp_path / "app.py"))
        assert _is_ignored(finding, entries, {}, tmp_path) is True


class TestOpengrepArgsTerminator:
    def test_batch_args_include_dash_dash_before_targets(self, tmp_path):
        adapter = OpengrepAdapter()
        target = tmp_path / "app.py"
        target.write_text("eval(x)\n")

        fake_result = MagicMock(returncode=0, stdout="{}", stderr="")
        with patch("subprocess.run", return_value=fake_result) as mock_run:
            adapter._run_batch([target], tmp_path, None, False, [])

        args = mock_run.call_args[0][0]
        assert "--" in args
        dash_idx = args.index("--")
        assert args[dash_idx + 1] == str(target)
        # Everything after "--" must be a target path, not a flag.
        assert all(not a.startswith("-") for a in args[dash_idx + 1:])

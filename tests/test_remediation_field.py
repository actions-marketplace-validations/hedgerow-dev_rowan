"""Regression tests for GitHub issue #83: rule remediation ('fix:') text.

The remediation-guidance feature was fully wired end-to-end (loader ->
Finding.metadata["remediation"] -> reporters) but no rule declared a `fix:`
field, so every finding's `Fix:` line was silently empty. At the time this
was fixed, Opengrep 1.22.0's SARIF output didn't propagate `metadata:`
fields at all, so remediation text needed a conversion-manifest side-channel
(extended to also cover native taint rules) to reach a Finding on the
default engine path. Issue #118 later replaced the internal SARIF parse
with Opengrep's native `--json` output, which *does* carry the full
metadata: block inline per result -- so remediation (like category/severity/
cwe) now flows directly from `extra.metadata.fix` at parse time, with no
manifest lookup needed at all. These tests still hold: they assert the
end-to-end behavior (a `Fix:` line reaches the report), not the specific
mechanism that delivers it.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest
import yaml

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline
from rowan.reporters import to_text
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
_adapter = OpengrepAdapter()


def _load_converter_module():
    path = Path(__file__).parent.parent / "scripts" / "convert_neuroscan_to_opengrep.py"
    spec = importlib.util.spec_from_file_location("convert_neuroscan_to_opengrep", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class TestConverterFixPassthrough:
    """Round-trip: authoring `fix:` on a source rule must survive conversion
    into both the converted rule's own metadata and the manifest entry."""

    def test_top_level_fix_field_propagates(self):
        conv = _load_converter_module()
        rule = {
            "id": "TEST-FIX-001",
            "severity": "critical",
            "category": "injection",
            "cwe": [94],
            "fix": "use a safe alternative",
            "languages": ["python"],
            "patterns": [r"eval\("],
            "message": "test rule",
        }
        converted, manifest, _warnings = conv.build_converted_rule(rule)
        assert converted["metadata"]["fix"] == "use a safe alternative"
        assert manifest["fix"] == "use a safe alternative"

    def test_metadata_nested_fix_field_propagates(self):
        """Variant B: fix authored under metadata: instead of top-level."""
        conv = _load_converter_module()
        rule = {
            "id": "TEST-FIX-002",
            "severity": "high",
            "metadata": {"category": "path_traversal", "cwe": [22], "fix": "canonicalize the path"},
            "languages": ["python"],
            "patterns": [r"open\("],
            "message": "test rule",
        }
        converted, manifest, _warnings = conv.build_converted_rule(rule)
        assert converted["metadata"]["fix"] == "canonicalize the path"
        assert manifest["fix"] == "canonicalize the path"

    def test_missing_fix_field_omitted_not_empty_string(self):
        conv = _load_converter_module()
        rule = {
            "id": "TEST-FIX-003",
            "severity": "low",
            "category": "general",
            "languages": ["python"],
            "patterns": [r"foo\("],
            "message": "test rule",
        }
        converted, manifest, _warnings = conv.build_converted_rule(rule)
        assert "fix" not in converted["metadata"]
        assert "fix" not in manifest


class TestRuleCoverageGuardrail:
    """Every CRITICAL-severity regex rule and every native taint rule must
    declare remediation text -- this is the actual coverage this pass
    populated; a new high-severity rule landing without one should fail
    here rather than silently ship another empty Fix: line."""

    def test_critical_regex_rules_have_fix(self):
        missing = []
        for yaml_file in RULES_DIR.glob("*.yaml"):
            if "converted" in str(yaml_file):
                continue
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            for rule in data.get("rules", []):
                if rule.get("mode") == "taint":
                    continue
                severity = str(rule.get("severity", "")).lower()
                if severity != "critical":
                    continue
                fix = rule.get("fix") or (rule.get("metadata") or {}).get("fix")
                if not fix:
                    missing.append((yaml_file.name, rule.get("id")))
        assert not missing, f"CRITICAL rules missing fix: text: {missing}"

    def test_taint_mode_rules_have_fix(self):
        missing = []
        for yaml_file in RULES_DIR.glob("*_taint.yaml"):
            data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                continue
            for rule in data.get("rules", []):
                if rule.get("mode") != "taint":
                    continue
                if not (rule.get("metadata") or {}).get("fix"):
                    missing.append((yaml_file.name, rule.get("id")))
        assert not missing, f"Taint rules missing metadata.fix text: {missing}"


@pytest.mark.skipif(not _adapter.is_installed(), reason="Opengrep binary not installed")
class TestRemediationSurfacesEndToEnd:
    """A scan against a known-vulnerable fixture must show a non-empty
    Fix: line in text output -- closes the loop the CHANGELOG claims is
    closed (issue #83's own acceptance criterion)."""

    def test_regex_engine_finding_shows_fix_line(self, tmp_path):
        """Default (non-legacy) engine path: converted regex rule NS-AIML-001
        (trust_remote_code=True) has a top-level fix: -- verify it survives
        through the conversion manifest into the report."""
        (tmp_path / "app.py").write_text(
            "from transformers import AutoModel\n"
            "AutoModel.from_pretrained('some/model', trust_remote_code=True)\n",
            encoding="utf-8",
        )
        config = ScanConfig(target=tmp_path, no_sca=True, no_cross_file=True, languages=["python"])
        result = ScanPipeline(config).run()
        matches = [f for f in result.findings if f.rule_id == "NS-AIML-001"]
        assert matches, "expected NS-AIML-001 to fire on this fixture"
        assert matches[0].metadata.get("remediation"), "NS-AIML-001 finding missing remediation metadata"
        text = to_text(result)
        assert "Fix:" in text

    def test_taint_mode_finding_shows_fix_line(self, tmp_path):
        """Native taint rule TNT-DESER-001 (pickle.load reaches from a
        request source) -- verify remediation reaches the report via
        OpengrepAdapter's direct --json metadata parsing (issue #118)."""
        (tmp_path / "app.py").write_text(
            "import pickle\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    data = request.args.get('payload')\n"
            "    return pickle.load(data)\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path, no_sca=True, no_cross_file=True, languages=["python"],
        )
        result = ScanPipeline(config).run()
        matches = [f for f in result.findings if f.rule_id == "TNT-DESER-001"]
        assert matches, "expected TNT-DESER-001 to fire on this fixture"
        assert matches[0].metadata.get("remediation"), "TNT-DESER-001 finding missing remediation metadata"
        text = to_text(result)
        assert "Fix:" in text

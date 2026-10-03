"""Taint rule YAML validation tests.

Verifies that all *_taint.yaml files parse correctly, have required fields,
and contain no duplicate IDs.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"


def _load_taint_files() -> list[tuple[str, list[dict]]]:
    results = []
    for f in sorted(RULES_DIR.glob("*_taint.yaml")):
        with open(f, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        rules = data.get("rules", [])
        results.append((f.name, rules))
    return results


def _all_taint_rules() -> list[tuple[str, dict]]:
    out = []
    for fname, rules in _load_taint_files():
        for rule in rules:
            out.append((fname, rule))
    return out


class TestTaintRuleYAMLValidity:

    def test_all_taint_files_parse(self):
        files = list(RULES_DIR.glob("*_taint.yaml"))
        assert len(files) > 0, "No taint rule files found"
        for f in files:
            with open(f, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
            assert "rules" in data, f"{f.name} missing 'rules' key"
            assert isinstance(data["rules"], list), f"{f.name} 'rules' is not a list"

    def test_all_rules_have_id(self):
        for fname, rule in _all_taint_rules():
            assert "id" in rule, f"{fname}: rule missing 'id'"
            assert isinstance(rule["id"], str), f"{fname}: rule id not a string"
            assert len(rule["id"]) > 0, f"{fname}: rule id is empty"

    def test_all_rules_have_mode_taint(self):
        for fname, rule in _all_taint_rules():
            assert rule.get("mode") == "taint", (
                f"{fname}: rule {rule.get('id')} has mode={rule.get('mode')}, expected 'taint'"
            )

    def test_all_rules_have_severity(self):
        valid_severities = {"ERROR", "WARNING", "INFO"}
        for fname, rule in _all_taint_rules():
            sev = rule.get("severity")
            assert sev in valid_severities, (
                f"{fname}: rule {rule.get('id')} has severity={sev}, "
                f"expected one of {valid_severities}"
            )

    def test_all_rules_have_languages(self):
        for fname, rule in _all_taint_rules():
            langs = rule.get("languages", [])
            assert isinstance(langs, list), f"{fname}: rule {rule.get('id')} languages not a list"
            assert len(langs) > 0, f"{fname}: rule {rule.get('id')} has no languages"

    def test_all_rules_have_sources(self):
        for fname, rule in _all_taint_rules():
            sources = rule.get("pattern-sources", [])
            assert isinstance(sources, list), (
                f"{fname}: rule {rule.get('id')} pattern-sources not a list"
            )
            assert len(sources) > 0, (
                f"{fname}: rule {rule.get('id')} has no pattern-sources"
            )

    def test_all_rules_have_sinks(self):
        for fname, rule in _all_taint_rules():
            sinks = rule.get("pattern-sinks", [])
            assert isinstance(sinks, list), (
                f"{fname}: rule {rule.get('id')} pattern-sinks not a list"
            )
            assert len(sinks) > 0, (
                f"{fname}: rule {rule.get('id')} has no pattern-sinks"
            )

    def test_all_rules_have_message(self):
        for fname, rule in _all_taint_rules():
            msg = rule.get("message", "")
            assert isinstance(msg, str), f"{fname}: rule {rule.get('id')} message not a string"
            assert len(msg.strip()) > 0, f"{fname}: rule {rule.get('id')} has empty message"

    def test_no_duplicate_taint_rule_ids(self):
        seen: dict[str, str] = {}
        for fname, rule in _all_taint_rules():
            rule_id = rule.get("id", "")
            if rule_id in seen:
                pytest.fail(
                    f"Duplicate taint rule ID '{rule_id}' in {fname} "
                    f"(first seen in {seen[rule_id]})"
                )
            seen[rule_id] = fname

    def test_rule_ids_follow_conventions(self):
        # LC-HARDEN- covers the LangChain hardening taint family
        # (langchain_hardening_taint.yaml).
        valid_prefixes = ("TNT-", "tnt-", "LC-HARDEN-")
        for fname, rule in _all_taint_rules():
            rule_id = rule.get("id", "")
            assert any(rule_id.startswith(p) for p in valid_prefixes), (
                f"{fname}: rule '{rule_id}' does not follow TNT-* convention"
            )

    def test_metadata_has_cwe(self):
        for fname, rule in _all_taint_rules():
            meta = rule.get("metadata", {})
            if meta:
                cwe = meta.get("cwe")
                if cwe is not None:
                    assert isinstance(cwe, list), (
                        f"{fname}: rule {rule.get('id')} cwe should be a list"
                    )

    def test_metadata_has_category(self):
        for fname, rule in _all_taint_rules():
            meta = rule.get("metadata", {})
            if meta:
                cat = meta.get("category")
                if cat is not None:
                    assert isinstance(cat, str), (
                        f"{fname}: rule {rule.get('id')} category should be a string"
                    )

    def test_total_taint_rule_count(self):
        total = len(_all_taint_rules())
        assert total >= 60, f"Expected at least 60 taint rules, got {total}"

    def test_multi_language_coverage(self):
        languages: set[str] = set()
        for _, rule in _all_taint_rules():
            for lang in rule.get("languages", []):
                languages.add(lang)
        expected = {"python", "java", "javascript", "go", "csharp"}
        missing = expected - languages
        assert len(missing) == 0, f"Missing taint rules for languages: {missing}"

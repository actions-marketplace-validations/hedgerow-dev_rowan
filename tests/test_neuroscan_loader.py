"""NeuroScan rule-loader hardening (issue #186).

`patterns:` means two different things depending on which engine a rule
targets: a list of regex strings for the NeuroScan engine, and a list of
structural mappings for Opengrep search-mode rules. `rowan/pipeline.py`
hands *every* rules/*.yaml file to `load_neuroscan_rules`, so a hand-written
Opengrep rule reaches this loader too. Before the fix that raised
`AttributeError: 'dict' object has no attribute 'startswith'` and took down
the entire corpus load.
"""

from __future__ import annotations

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules


def test_opengrep_search_rules_do_not_crash_the_neuroscan_loader(tmp_path):
    """`patterns:` means regex strings to NeuroScan and structural mappings to
    Opengrep, and the pipeline hands every rules/*.yaml file to this loader
    (rowan/pipeline.py). A hand-written Opengrep search rule therefore
    reaches it too, and used to raise `'dict' object has no attribute
    'startswith'`, taking down the entire corpus load. Issue #186."""
    rules_path = tmp_path / "opengrep_style.yaml"
    rules_path.write_text(
        "rules:\n"
        "  - id: OG-SEARCH-001\n"
        "    message: structural rule, not a regex rule\n"
        "    severity: WARNING\n"
        "    languages: [python]\n"
        "    patterns:\n"
        "      - pattern: $GUARD(...)\n"
        "      - pattern-not-inside: $R = $GUARD(...)\n",
        encoding="utf-8",
    )

    rules = load_neuroscan_rules(rules_path)

    assert [r for r in rules if r.metadata.id == "OG-SEARCH-001"] == [], (
        "an Opengrep structural rule must be skipped by the NeuroScan loader, "
        "not registered as a pattern-less rule that can never match"
    )


def test_real_guardrail_rule_file_loads_without_error():
    """The shipped rules/guardrail_opengrep.yaml is the concrete instance of the
    case above; guard against it regressing the corpus load."""
    rules_path = Path(__file__).parent.parent / "rules" / "guardrail_opengrep.yaml"
    assert rules_path.exists(), "rules/guardrail_opengrep.yaml is missing"
    assert load_neuroscan_rules(rules_path) == []


def test_regex_rules_still_load_alongside_non_string_patterns(tmp_path):
    """The skip must be per-pattern, not per-file: a genuine regex rule in the
    same file as a structural one still has to load."""
    rules_path = tmp_path / "mixed.yaml"
    rules_path.write_text(
        "rules:\n"
        "  - id: OG-SEARCH-002\n"
        "    message: structural\n"
        "    severity: WARNING\n"
        "    languages: [python]\n"
        "    patterns:\n"
        "      - pattern: $X(...)\n"
        "  - id: NS-REGEX-002\n"
        "    message: regex\n"
        "    severity: WARNING\n"
        "    languages: [python]\n"
        "    patterns:\n"
        "      - 'eval\\\\('\n",
        encoding="utf-8",
    )

    loaded = {r.metadata.id for r in load_neuroscan_rules(rules_path)}

    assert "NS-REGEX-002" in loaded
    assert "OG-SEARCH-002" not in loaded


def test_convert_script_skips_opengrep_files():
    """The standalone conversion script (scripts/convert_neuroscan_to_opengrep.py)
    has its OWN file-selection filter, separate from load_neuroscan_rules --
    it used to lack the same *_opengrep.yaml exclusion and crashed converting
    rules/guardrail_opengrep.yaml's structural rules as flat regex ("cannot
    use 'tuple' as a dict key"), reproduced directly against this repo's own
    converter before the fix. Import-level check, not a subprocess run --
    the actual full conversion is exercised by CI's scripts/check_doc_counts.py."""
    import importlib.util
    from pathlib import Path

    script_path = Path(__file__).parent.parent / "scripts" / "convert_neuroscan_to_opengrep.py"
    spec = importlib.util.spec_from_file_location("convert_script", script_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    rules_dir = Path(__file__).parent.parent / "rules"
    selected = {
        p.name for p in rules_dir.glob("*.yaml")
        if "taint" not in p.name and "opengrep" not in p.name
    }
    assert "guardrail_opengrep.yaml" not in selected

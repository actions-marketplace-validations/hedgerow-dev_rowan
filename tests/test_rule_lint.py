"""Tests for the rule quality linter (rowan.tools.lint_rules).

These act as a regression guard so that an over-broad taint rule like the
old ``TNT-ML-002`` (whose source ``$FUNC(...)`` matched every function call)
can never be merged again.
"""

from __future__ import annotations

from pathlib import Path

from rowan.tools.lint_rules import find_broad_framework_call_patterns, lint_rules

REPO_RULES_DIR = Path(__file__).parents[1] / "rules"


def test_no_overbroad_taint_sources():
    violations = lint_rules(REPO_RULES_DIR)
    assert violations == [], "Rule packs have quality violations:\n" + "\n".join(violations)


def test_linter_catches_overbroad(tmp_path):
    rule_file = tmp_path / "bad_taint.yaml"
    rule_file.write_text(
        """
rules:
  - id: TNT-BAD-001
    mode: taint
    message: overly broad source
    severity: WARNING
    languages: [python]
    pattern-sources:
      - patterns:
          - pattern-either:
              - pattern: $FUNC(...)
    pattern-sinks:
      - patterns:
          - pattern-either:
              - pattern: eval($CODE)
""",
        encoding="utf-8",
    )

    violations = lint_rules(tmp_path)
    assert violations, "linter failed to flag a universal $FUNC(...) source"
    assert any("TNT-BAD-001" in v and "pattern-sources" in v for v in violations)


def test_linter_accepts_metavariable_anchored_by_pattern_inside(tmp_path):
    """A bare `$PARAM` constrained to the parameters of a `@Tool` method is
    the shape the Java tool-parameter rules use; it is not universal."""
    rule_file = tmp_path / "tool_taint.yaml"
    rule_file.write_text(
        """
rules:
  - id: TNT-TOOL-001
    mode: taint
    message: tool parameter to exec
    severity: ERROR
    languages: [java]
    pattern-sources:
      - patterns:
          - pattern: $PARAM
          - pattern-inside: |
              @Tool(...)
              $RET $METHOD(..., $TYPE $PARAM, ...) { ... }
    pattern-sinks:
      - pattern: (Runtime $R).exec(...)
""",
        encoding="utf-8",
    )

    violations = lint_rules(tmp_path)
    assert violations == [], violations


def test_linter_catches_duplicate_ids(tmp_path):
    rule_file = tmp_path / "dupe.yaml"
    rule_file.write_text(
        """
rules:
  - id: TNT-DUP-001
    mode: taint
    message: first
    severity: WARNING
    languages: [python]
    pattern-sources:
      - pattern: request.args.get($X)
    pattern-sinks:
      - pattern: eval($X)
  - id: TNT-DUP-001
    mode: taint
    message: second
    severity: WARNING
    languages: [python]
    pattern-sources:
      - pattern: request.form.get($X)
    pattern-sinks:
      - pattern: exec($X)
""",
        encoding="utf-8",
    )

    violations = lint_rules(tmp_path)
    assert any("duplicate" in v.lower() and "TNT-DUP-001" in v for v in violations)


# ── Broad framework call detector tests (synthetic YAML only) ────────


def test_broad_call_flags_bare_pattern(tmp_path):
    """A pattern matching a bare constructor call without context IS flagged."""
    rule_file = tmp_path / "bare_call.yaml"
    rule_file.write_text(
        r"""
rules:
  - id: NS-TEST-BARE
    name: some broad rule
    severity: WARNING
    languages: [python]
    patterns:
      - 'ChatPromptTemplate\s*\('
    message: test
""",
        encoding="utf-8",
    )
    warnings = find_broad_framework_call_patterns(tmp_path)
    assert warnings, "bare ChatPromptTemplate\\s*\\( should be flagged"
    assert any("NS-TEST-BARE" in w for w in warnings)


def test_broad_call_ignores_context_token_pattern(tmp_path):
    """A pattern containing a user-input context token is NOT flagged."""
    rule_file = tmp_path / "context_token.yaml"
    rule_file.write_text(
        r"""
rules:
  - id: NS-TEST-CTX
    name: pattern with request
    severity: WARNING
    languages: [python]
    patterns:
      - 'ChatPromptTemplate\s*\([^)]*request'
    message: test
""",
        encoding="utf-8",
    )
    warnings = find_broad_framework_call_patterns(tmp_path)
    assert not warnings, f"pattern with 'request' context should NOT be flagged, got: {warnings}"


def test_broad_call_ignores_danger_token_pattern(tmp_path):
    """A pattern containing a danger-operation token is NOT flagged."""
    rule_file = tmp_path / "danger_token.yaml"
    rule_file.write_text(
        r"""
rules:
  - id: NS-TEST-DANGER
    name: pickle loads
    severity: WARNING
    languages: [python]
    patterns:
      - 'pickle\.loads?\s*\('
    message: test
""",
        encoding="utf-8",
    )
    warnings = find_broad_framework_call_patterns(tmp_path)
    assert not warnings, f"pattern with 'pickle' danger token should NOT be flagged, got: {warnings}"

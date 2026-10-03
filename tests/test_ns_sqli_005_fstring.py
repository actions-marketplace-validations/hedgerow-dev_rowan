"""NS-SQLI-005 could not cross a quote, so it missed the commonest SQLi shape.

The pattern used `[^"']*` on both sides of the SQL keyword, which excludes
BOTH quote characters. In `f"SELECT ... WHERE name = '{x}'"` -- a quoted
interpolation, the most common form there is -- the inner `'` sits between
the keyword and the `{`, so the match could never reach the brace.

Widening to `.{0,200}?` fixes that but lets the match leave the f-string
entirely, pairing a SQL keyword in one string with a `{` in a later one.
Each alternative here excludes only its own closing quote, which stays
inside the literal while allowing the opposite quote character in it.
"""

from __future__ import annotations

import re

import yaml

from rowan.config import ScanConfig

_RULE_ID = "NS-SQLI-005"


def _patterns() -> list[re.Pattern]:
    path = ScanConfig.default_rules_dir() / "neuroscan.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    rule = next(r for r in data["rules"] if r["id"] == _RULE_ID)
    return [re.compile(p) for p in rule["patterns"]]


def _matches(code: str) -> bool:
    return any(p.search(code) for p in _patterns())


class TestQuotedInterpolationIsCaught:
    def test_single_quoted_value_inside_double_quoted_fstring(self) -> None:
        assert _matches("""query = f"SELECT * FROM users WHERE name = '{name}'" """)

    def test_double_quoted_value_inside_single_quoted_fstring(self) -> None:
        assert _matches("""query = f'SELECT * FROM users WHERE name = "{name}"' """)

    def test_unquoted_interpolation_still_caught(self) -> None:
        assert _matches('query = f"SELECT * FROM users WHERE id = {uid}"')

    def test_order_by_shape(self) -> None:
        assert _matches('q = f"ORDER BY {sort}"')


class TestMatchStaysInsideTheLiteral:
    """The precision guarantee: a keyword in one string must not pair with a
    brace in a different one. This is what `.{0,200}?` gave up."""

    def test_keyword_and_brace_in_different_strings(self) -> None:
        assert not _matches('msg = f"select a plan" ; other = "{}".format(x)')

    def test_keyword_in_one_fstring_brace_in_a_later_one(self) -> None:
        assert not _matches('log = f"user where clause built"; path = f"{base}/x"')

    def test_plain_prose_without_interpolation(self) -> None:
        assert not _matches('msg = f"select an option from the menu"')


def test_source_and_converted_rules_agree() -> None:
    """The converted copy is what actually executes; a source-only edit is
    inert until the converter runs."""
    converted = yaml.safe_load(
        (ScanConfig.default_rules_dir() / "converted" / "neuroscan.yaml").read_text(encoding="utf-8")
    )
    rule = next(r for r in converted["rules"] if r["id"] == _RULE_ID)
    blob = yaml.safe_dump(rule)
    assert "[^\"]" in blob and "[^']" in blob, (
        "converted rule still carries the old both-quotes exclusion -- "
        "re-run scripts/convert_neuroscan_to_opengrep.py"
    )


def test_english_prose_after_select_is_excluded() -> None:
    """`f"Select a model (1-{n})"` matched the `select ` keyword. SQL never
    puts an article after SELECT, so excluding it costs no detection. This
    was the only false-positive shape among 69 matches on llmware."""
    import yaml as _yaml

    path = ScanConfig.default_rules_dir() / "neuroscan.yaml"
    rule = next(
        r for r in _yaml.safe_load(path.read_text(encoding="utf-8"))["rules"]
        if r["id"] == _RULE_ID
    )
    nots = [re.compile(p) for p in rule["pattern-not"]]

    for prose in (
        'prompt = f"\\nSelect a model (1-{num_models}): "',
        'msg = f"select an option from {menu}"',
        'msg = f"Select the row for {name}"',
    ):
        assert any(n.search(prose) for n in nots), prose

    # A real query must NOT be excluded by the new pattern-not.
    real = """query = f"SELECT * FROM users WHERE name = '{name}'" """
    assert not any(n.search(real) for n in nots)

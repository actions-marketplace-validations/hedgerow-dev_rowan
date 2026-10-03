"""Regression tests for rowan/analysis/source_tracer.py."""

from __future__ import annotations

from rowan.analysis.source_tracer import _extract_root_var


class TestExtractRootVarFstringGuard:
    """_extract_root_var must short-circuit on f-strings (they're handled by
    _classify_fstring) instead of extracting "f" as a bogus root var (#116)."""

    def test_fstring_single_quote_returns_none(self):
        assert _extract_root_var("f'{prefix}_{uuid}_Node'") is None

    def test_fstring_double_quote_returns_none(self):
        assert _extract_root_var('f"{x}_{y}"') is None

    def test_plain_single_quoted_string_returns_none(self):
        assert _extract_root_var("'literal'") is None

    def test_plain_double_quoted_string_returns_none(self):
        assert _extract_root_var('"literal"') is None

    def test_identifier_starting_with_f_is_not_treated_as_fstring(self):
        assert _extract_root_var("foo.bar") == "foo"

    def test_plain_identifier(self):
        assert _extract_root_var("request.args.get('q')") == "request"

    def test_attribute_chain(self):
        assert _extract_root_var("dify_config.MARKETPLACE_API_URL") == "dify_config"

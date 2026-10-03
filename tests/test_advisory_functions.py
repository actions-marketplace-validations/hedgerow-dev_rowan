"""Tests for per-CVE vulnerable-function extraction from advisory text.

Precision-first: only qualified, in-namespace symbols named inside code spans
are extracted, so a wrong extraction can never silently downgrade a real CVE.
"""

from __future__ import annotations

from rowan.core.advisory_functions import extract_vulnerable_symbols
from rowan.core.phantom_deps import import_roots_for_distribution


class TestImportRootsForDistribution:
    def test_default_is_own_name(self):
        assert "requests" in import_roots_for_distribution("requests")

    def test_includes_alias_roots(self):
        # pillow is imported as PIL; pyyaml as yaml.
        assert import_roots_for_distribution("pillow") >= {"pillow", "pil"}
        assert import_roots_for_distribution("pyyaml") >= {"pyyaml", "yaml"}


class TestExtractVulnerableSymbols:
    def test_qualified_symbol_in_backticks(self):
        details = "The vulnerability is in `requests.get()` when `verify=False`."
        assert extract_vulnerable_symbols(details, "requests") == ["requests.get"]

    def test_symbol_in_fenced_block(self):
        details = "Example:\n```python\nimport yaml\nyaml.load(data)\n```\n"
        assert "yaml.load" in extract_vulnerable_symbols(details, "pyyaml")

    def test_out_of_namespace_symbol_ignored(self):
        # An advisory describing impact via os.system must not attribute that
        # to the package (it's not the package's own API).
        details = "Leads to code execution via `os.system(payload)`."
        assert extract_vulnerable_symbols(details, "requests") == []

    def test_prose_mention_not_extracted(self):
        # Only code spans count -- a dotted name in plain prose is ignored.
        details = "The requests.get function is affected in some versions."
        assert extract_vulnerable_symbols(details, "requests") == []

    def test_bare_name_not_extracted(self):
        details = "Call `load()` to trigger the bug."
        assert extract_vulnerable_symbols(details, "pyyaml") == []

    def test_alias_namespace_head_accepted(self):
        details = "Fixed in `PIL.Image.open` handling."
        assert extract_vulnerable_symbols(details, "pillow") == ["PIL.Image.open"]

    def test_deduplicates_preserving_order(self):
        details = "`a.foo` then `a.bar` then `a.foo` again."
        assert extract_vulnerable_symbols(details, "a") == ["a.foo", "a.bar"]

    def test_empty_details_returns_empty(self):
        assert extract_vulnerable_symbols("", "requests") == []
        assert extract_vulnerable_symbols("some text", "") == []

    def test_no_code_spans_returns_empty(self):
        assert extract_vulnerable_symbols("plain prose, no code here", "requests") == []

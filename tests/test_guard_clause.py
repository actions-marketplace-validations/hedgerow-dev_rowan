"""Unit tests for the guard-clause post-filter (GitHub issue #160).

These exercise `rowan.analysis.guard_clause` directly against a parsed
AST -- no Opengrep binary required, unlike the live-scan regression tests in
`tests/test_taint_sanitizer_soundness.py::TestGuardClausePostFilter`, which
cover the same shapes end-to-end through a real Opengrep scan +
EnrichmentPass. Keeping a pure-unit layer here isolates the guard-detection
logic itself from an unrelated, pre-existing enrichment quirk
(`_apply_source_confidence` mis-resolving a bare `request.args.get(...)`
snippet's origin) that collapses confidence on *every* finding sourced that
way regardless of guard-clause suppression -- see the note in that test
class. Testing `find_dominating_guard` in isolation gives an unambiguous
signal for each of the issue's precision requirements.
"""

from __future__ import annotations

import ast

from rowan.analysis.guard_clause import (
    check_guard_suppression,
    extract_sink_var_name,
    find_dominating_guard,
)
from rowan.core.findings import TaintFlow, TaintNode


def _find_sink_line(source: str, marker: str) -> int:
    for i, line in enumerate(source.splitlines(), start=1):
        if marker in line:
            return i
    raise AssertionError(f"marker {marker!r} not found in source")


class TestMembershipGuardShape:
    def test_early_return_not_in_allowlist_suppresses(self):
        src = (
            "def fetch(url):\n"
            "    if url not in ALLOWED_URLS:\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") == "membership"

    def test_blocklist_membership_suppresses(self):
        """`if x in BLOCKLIST: return` -- membership shape works either way
        round; what matters is that the True branch (whichever test made it
        true) unconditionally exits."""
        src = (
            "def fetch(url):\n"
            "    if url in BLOCKLIST:\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") == "membership"

    def test_positive_allowlist_membership_does_not_suppress(self):
        """Returning for an allowed value leaves disallowed values at the sink."""
        source = (
            "def fetch(url):\n"
            "    if url in ALLOWED_URLS:\n"
            "        return None\n"
            "    return requests.get(url)  # sink\n"
        )
        tree = ast.parse(source)
        sink_line = _find_sink_line(source, "# sink")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_negated_blocklist_membership_does_not_suppress(self):
        source = (
            "def fetch(url):\n"
            "    if not url in BLOCKLIST:\n"
            "        return None\n"
            "    return requests.get(url)  # sink\n"
        )
        tree = ast.parse(source)
        sink_line = _find_sink_line(source, "# sink")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_negated_allowlist_nonmembership_does_not_suppress(self):
        source = (
            "def fetch(url):\n"
            "    if not url not in ALLOWED_URLS:\n"
            "        return None\n"
            "    return requests.get(url)  # sink\n"
        )
        tree = ast.parse(source)
        sink_line = _find_sink_line(source, "# sink")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_alias_one_hop_suppresses(self):
        """The guard test can reference a variable assigned directly from
        the tainted one, one hop earlier."""
        src = (
            "def fetch(url):\n"
            "    safe_url = url\n"
            "    if safe_url not in ALLOWED_URLS:\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") == "membership"


class TestPrefixGuardShape:
    def test_not_startswith_constant_suppresses(self):
        src = (
            "def fetch(url):\n"
            "    if not url.startswith('https://api.example.com/'):\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") == "prefix"

    def test_not_startswith_all_caps_name_suppresses(self):
        src = (
            "def fetch(url):\n"
            "    if not url.startswith(ALLOWED_PREFIX):\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") == "prefix"

    def test_not_startswith_unbound_variable_does_not_suppress(self):
        """An arbitrary (non-constant, non-ALL_CAPS) variable argument must
        not be accepted -- matches the #87 precedent that an unpinned
        `.startswith()` isn't a sound guard on its own."""
        src = (
            "def fetch(url, prefix):\n"
            "    if not url.startswith(prefix):\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None


class TestContainmentGuardShape:
    def test_not_is_relative_to_suppresses(self):
        src = (
            "def read(path):\n"
            "    if not path.is_relative_to(BASE_DIR):\n"
            "        return None\n"
            "    return open(path)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "open(path)")
        assert find_dominating_guard(tree, sink_line, "path") == "containment"

    def test_commonpath_inequality_suppresses(self):
        src = (
            "def read(path):\n"
            "    if os.path.commonpath([BASE_DIR, path]) != BASE_DIR:\n"
            "        return None\n"
            "    return open(path)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "open(path)")
        assert find_dominating_guard(tree, sink_line, "path") == "containment"


class TestNegativePrecisionRequirements:
    """Each mirrors a precision requirement from GitHub issue #160."""

    def test_guard_on_different_variable_does_not_suppress(self):
        src = (
            "def fetch(url, other):\n"
            "    if other not in ALLOWED_URLS:\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_guard_body_that_does_not_exit_does_not_suppress(self):
        src = (
            "def fetch(url):\n"
            "    if url not in ALLOWED_URLS:\n"
            "        logging.warning('blocked: %s', url)\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_guard_after_sink_does_not_suppress(self):
        src = (
            "def fetch(url):\n"
            "    result = requests.get(url)\n"
            "    if url not in ALLOWED_URLS:\n"
            "        return None\n"
            "    return result\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_retaint_after_guard_does_not_suppress(self):
        src = (
            "def fetch(url):\n"
            "    if url not in ALLOWED_URLS:\n"
            "        return None\n"
            "    url = get_fresh_url()\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_guard_inside_loop_with_sink_outside_does_not_suppress(self):
        src = (
            "def fetch(url):\n"
            "    for _ in range(3):\n"
            "        if url not in ALLOWED_URLS:\n"
            "            return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_guard_in_mutually_exclusive_branch_does_not_suppress(self):
        """A guard living in one arm of an unrelated if/else must not
        dominate a sink in the other arm -- same numeric nesting depth,
        but not a genuine sibling on the sink's actual control-flow path."""
        src = (
            "def fetch(url, cond):\n"
            "    if cond:\n"
            "        if url not in ALLOWED_URLS:\n"
            "            return None\n"
            "    else:\n"
            "        return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None

    def test_conditionally_assigned_alias_does_not_suppress(self):
        """Confirmed bug found in code review: `_collect_aliases_before` used
        to scan the WHOLE function's flattened statements for any earlier
        `X = var_name` assignment, with no check that the assignment
        actually dominates the guard. Here `checked = url` only happens in
        the `if url in TRUSTED_CACHE:` branch -- the `else` branch
        reassigns `checked` to an unrelated hardcoded, always-allowed
        constant. The guard `if checked not in ALLOWED: return` therefore
        does NOT guarantee `url` was validated (when `url` isn't in
        TRUSTED_CACHE, `checked` becomes the dummy value, which passes the
        ALLOWED check regardless of the real `url`), so this must not
        suppress -- a real SSRF via `requests.get(url)` when `url` isn't
        cached must still be flagged at full confidence."""
        src = (
            "def fetch(url):\n"
            "    if url in TRUSTED_CACHE:\n"
            "        checked = url\n"
            "    else:\n"
            "        checked = 'http://example.com'\n"
            "    if checked not in ALLOWED:\n"
            "        return\n"
            "    requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        assert find_dominating_guard(tree, sink_line, "url") is None


class TestExtractSinkVarName:
    def test_prefers_last_intermediate_var(self):
        tf = TaintFlow(
            source=TaintNode(file_path="x.py", line=1, snippet="request.args.get('url')"),
            sink=TaintNode(file_path="x.py", line=3, snippet="requests.get(url)"),
            intermediate=[TaintNode(file_path="x.py", line=1, snippet="url")],
        )
        assert extract_sink_var_name(tf) == "url"

    def test_falls_back_to_sink_snippet_call_argument(self):
        tf = TaintFlow(
            source=TaintNode(file_path="x.py", line=1, snippet="request.args.get('url')"),
            sink=TaintNode(file_path="x.py", line=1, snippet="requests.get(url)"),
            intermediate=[],
        )
        assert extract_sink_var_name(tf) == "url"

    def test_no_named_variable_in_fully_inline_sink_returns_none(self):
        tf = TaintFlow(
            source=TaintNode(file_path="x.py", line=1, snippet="request.args.get('url')"),
            sink=TaintNode(
                file_path="x.py", line=1,
                snippet="requests.get(request.args.get('url'))",
            ),
            intermediate=[],
        )
        assert extract_sink_var_name(tf) is None

    def test_none_taint_flow_returns_none(self):
        assert extract_sink_var_name(None) is None


class TestCheckGuardSuppressionEntryPoint:
    def test_full_entry_point_matches_via_taint_flow(self):
        src = (
            "def fetch(url):\n"
            "    if url not in ALLOWED_URLS:\n"
            "        return None\n"
            "    return requests.get(url)\n"
        )
        tree = ast.parse(src)
        sink_line = _find_sink_line(src, "requests.get")
        tf = TaintFlow(
            source=TaintNode(file_path="x.py", line=1, snippet="request.args.get('url')"),
            sink=TaintNode(file_path="x.py", line=sink_line, snippet="requests.get(url)"),
            intermediate=[TaintNode(file_path="x.py", line=1, snippet="url")],
        )
        assert check_guard_suppression(tree, sink_line, tf) == "membership"

    def test_no_taint_flow_returns_none(self):
        tree = ast.parse("def f():\n    pass\n")
        assert check_guard_suppression(tree, 1, None) is None

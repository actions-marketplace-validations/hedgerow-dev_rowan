"""Guard-clause post-filter for the early-return sanitizer gap (GitHub issue #160).

`docs/taint-sanitizer-audit.md`'s DEF-40 correction documents a verified
Opengrep engine limitation: a `pattern-sanitizers`/`pattern-not-inside` rule
can suppress a positive-branch or if/else guard (both are syntactic
containment -- the sink call lexically sits inside the guarded branch), but
it cannot recognize the early-return idiom, because the sink is a *sibling*
statement, not a contained one:

    def fetch(url):
        if url not in ALLOWED_URLS:
            return None
        return requests.get(url)   # still flagged, even though this is safe

This module runs AFTER Opengrep, on findings that already carry a
`taint_flow` (every Opengrep taint finding does, since `--dataflow-traces`
is always passed -- see `rowan/taint/opengrep_adapter.py`). It parses
the containing file, locates the function enclosing the sink line, and
looks for a **dominating guard**: an `if <test>: <return|raise|exit>` that

  - is a genuine sibling of the sink on its actual control-flow path (not
    merely "at the same numeric nesting depth somewhere in the function" --
    a guard living in a mutually-exclusive branch, e.g. the *other* arm of
    an unrelated if/else, or inside a loop whose body the sink sits outside
    of, is deliberately excluded -- see `_collect_dominating_candidates`),
  - appears earlier in execution order than the sink,
  - whose body unconditionally exits (the last statement is a
    return/raise, or a bare `sys.exit(...)`/`os.abort()`/`exit(...)` call),
  - whose test references the tainted variable (or a variable assigned
    directly from it one hop earlier) via one of four closed guard shapes:
    membership (`x not in NAME` / `x in NAME`), prefix (`not
    x.startswith(CONST_OR_ALL_CAPS)`), containment (`not
    path.is_relative_to(base)`, or a `commonpath`/`commonprefix` inequality
    comparison), or **principal** (`x != request.user.id`, or an
    authorization-decision call receiving `x`) -- added for `TNT-AUTHZ-001`
    (issue #185).

The principal shape is here rather than in `pattern-sanitizers` on purpose.
Comparing a value against the current user does not *transform* it, so
modelling it as a taint sanitizer would clear taint for something that
neutralized nothing -- exactly DEF-43's defect. Requiring the guarded branch
to exit is what makes it sound: the comparison demonstrably gated the flow.

This deliberately does NOT build a full CFG/dominator tree -- GitHub issue
#124 is the complete version of this; this is its narrower, already
well-specified early-return subset. The dominance primitive itself
(`_collect_dominating_candidates`/`_find_enclosing_function`) has since been
extracted to `rowan/analysis/dominance.py` so issue #124's other
consumers (`cross_file.py`'s `_classify_path_sanitizer`, `enrichment.py`'s
`_suppress_sanitizer_window`) can reuse it without duplicating this module's
recursive descend-only-into-the-taken-branch walk. A match downgrades the
finding's confidence (the caller, `EnrichmentPass`, sets it to <= 0.3) and
tags `metadata["guard_suppressed"]`; it never deletes the finding, matching
this project's "over-flagging accepted, silent false-negative not" stance.
"""

from __future__ import annotations

import ast
import re

from rowan.analysis.dominance import (
    collect_dominating_candidates as _collect_dominating_candidates,
)
from rowan.analysis.dominance import (
    find_enclosing_function as _find_enclosing_function,
)
from rowan.analysis.source_tracer import _extract_root_var
from rowan.analysis.stmt_walk import iter_body_statements
from rowan.core.authz_predicates import is_principal_expr
from rowan.core.findings import TaintFlow

#: Function/method names that denote an authorization decision. Used only in
#: combination with the tainted variable being passed in AND the guarded branch
#: exiting, so the bar stays high (see `_is_policy_engine_call`).
_POLICY_CALL_RE = re.compile(
    r"(?i)^(enforce|is_allowed|check_permission|check_access|has_perm|has_permission"
    r"|can|can_access|authorize|is_authorized|allow_request|permit)$"
)

_SIMPLE_IDENTIFIER_RE = re.compile(r"[a-zA-Z_]\w*")
_ALLOWLIST_NAME_RE = re.compile(r"(?i)(?:allow|trust|permit|approve|register|safe|valid)")
_BLOCKLIST_NAME_RE = re.compile(r"(?i)(?:block|deny|forbid|ban|reject)")

# ── guard-body "unconditionally exits" check ──────────────────────────────


def _is_exit_call(call: ast.Call) -> bool:
    """`sys.exit(...)`, `os.abort()`, or a bare `exit(...)`/`quit(...)`."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id in ("exit", "quit")
    if isinstance(func, ast.Attribute):
        if func.attr == "exit" and isinstance(func.value, ast.Name) and func.value.id == "sys":
            return True
        if func.attr == "abort" and isinstance(func.value, ast.Name) and func.value.id == "os":
            return True
    return False


def _body_unconditionally_exits(body: list[ast.stmt]) -> bool:
    """v1 heuristic: the guard's *last* statement is a return/raise/exit --
    deliberately not a full reachability analysis (matches the issue's
    narrow "if <test>: <return|raise|call to sys.exit/abort>" scope)."""
    if not body:
        return False
    last = body[-1]
    if isinstance(last, (ast.Return, ast.Raise)):
        return True
    return bool(
        isinstance(last, ast.Expr)
        and isinstance(last.value, ast.Call)
        and _is_exit_call(last.value)
    )


# ── guard-test shape recognizers ──────────────────────────────────────────


def _expr_is_var_ref(expr: ast.expr, var_name: str) -> bool:
    """True for a bare `var_name`, or an attribute chain rooted at it
    (`var_name.attr`)."""
    if isinstance(expr, ast.Name):
        return expr.id == var_name
    if isinstance(expr, ast.Attribute):
        return _expr_is_var_ref(expr.value, var_name)
    return False


def _contains_var_name(expr: ast.expr, var_name: str) -> bool:
    return any(isinstance(n, ast.Name) and n.id == var_name for n in ast.walk(expr))


def _is_membership_test(test: ast.expr, var_name: str) -> bool:
    """Recognize a rejecting allowlist or blocklist guard.

    An early return after ``x in ALLOWED`` proves the opposite of what this
    post-filter needs and must not suppress a finding.  ``x not in ALLOWED``
    is a rejecting allowlist guard.  Positive membership is accepted only for
    an explicitly named blocklist, where the exiting branch is also rejecting.
    """
    negated = isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)
    node = test.operand if negated else test
    if not (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and _expr_is_var_ref(node.left, var_name)
    ):
        return False
    op = node.ops[0]
    if not isinstance(op, (ast.In, ast.NotIn)):
        return False
    collection = node.comparators[0]
    if not isinstance(collection, ast.Name):
        return False
    # Normalize ``not (x in SET)`` / ``not (x not in SET)`` before applying
    # the collection's security semantics.  A rejecting branch is either
    # `x not in ALLOWLIST` or `x in BLOCKLIST`; the inverse forms send the
    # dangerous values onward and must never suppress a finding.
    effective_not_in = isinstance(op, ast.NotIn) != negated
    if effective_not_in:
        return bool(_ALLOWLIST_NAME_RE.search(collection.id))
    return bool(_BLOCKLIST_NAME_RE.search(collection.id))


def _is_prefix_test(test: ast.expr, var_name: str) -> bool:
    """`not x.startswith(CONST_OR_ALL_CAPS_NAME)` -- pinned to a string
    literal or an ALL_CAPS name, same bar #87 required of a sound
    sanitizer. An unbound `.startswith()` alone was already rejected as a
    sanitizer (docs/taint-sanitizer-audit.md, issue #87); this is different
    because the guarded branch must *also* unconditionally exit, which
    proves the call actually gated control flow rather than merely being
    present somewhere in the function."""
    if not (isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not)):
        return False
    inner = test.operand
    if not (
        isinstance(inner, ast.Call)
        and isinstance(inner.func, ast.Attribute)
        and inner.func.attr == "startswith"
        and _expr_is_var_ref(inner.func.value, var_name)
        and inner.args
    ):
        return False
    arg0 = inner.args[0]
    if isinstance(arg0, ast.Constant) and isinstance(arg0.value, str):
        return True
    return bool(isinstance(arg0, ast.Name) and arg0.id.isupper())


def _is_commonpath_call(expr: ast.expr) -> bool:
    return bool(
        isinstance(expr, ast.Call)
        and isinstance(expr.func, ast.Attribute)
        and expr.func.attr in ("commonpath", "commonprefix")
    )


def _is_containment_test(test: ast.expr, var_name: str) -> bool:
    """`not path.is_relative_to(base)`, or a `commonpath`/`commonprefix`
    inequality comparison -- reuses the same idioms
    `_classify_path_sanitizer`/`_feeds_containment_check` in
    `rowan/passes/cross_file.py` recognize for a full-function
    containment check, narrowed to a single guard test."""
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        if (
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr == "is_relative_to"
            and (
                _expr_is_var_ref(inner.func.value, var_name)
                or _contains_var_name(inner.func.value, var_name)
            )
        ):
            return True
    if isinstance(test, ast.Compare) and any(isinstance(op, ast.NotEq) for op in test.ops):
        for operand in (test.left, *test.comparators):
            if _is_commonpath_call(operand) and _contains_var_name(operand, var_name):
                return True
    return False


def _is_policy_engine_call(expr: ast.expr, var_name: str) -> bool:
    """A call to an authorization decision function that receives the
    variable, e.g. `enforcer.enforce(request.user.id, claimed, "read")`
    (Casbin), `opa.check(...)`, `user.has_perm(...)`, `can(...)`.

    Deliberately narrow: the call must both be named like an authorization
    decision AND receive the tainted variable, so a stray `check_format(x)`
    does not qualify. As with the other kinds, the guarded branch must also
    unconditionally exit, which is what proves the decision gated control
    flow rather than merely being computed.
    """
    if not isinstance(expr, ast.Call):
        return False
    name = None
    if isinstance(expr.func, ast.Attribute):
        name = expr.func.attr
    elif isinstance(expr.func, ast.Name):
        name = expr.func.id
    if not name or not _POLICY_CALL_RE.match(name):
        return False
    return any(_contains_var_name(a, var_name) for a in (*expr.args, *(k.value for k in expr.keywords)))


def _is_principal_comparison(test: ast.expr, var_name: str) -> bool:
    """`claimed_id != request.user.id` / `claimed_id == current_user.id` --
    the variable is compared against the *server-side* principal.

    This is the authorization-guard shape, and it is deliberately NOT a
    taint sanitizer: a comparison does not transform the value, so treating
    it as one would repeat DEF-43's mistake (clearing taint for something
    that neutralized nothing). It belongs here instead, where the guarded
    branch is additionally required to exit, so the comparison demonstrably
    gates the flow.

    Narrow on purpose: one side must reference the tainted variable and the
    other must be a recognized principal expression (`request.user`,
    `current_user`, `g.user`, `self.request.user`). A comparison against an
    arbitrary value is not an authorization check and must not suppress
    anything.
    """
    node = test
    if isinstance(node, ast.UnaryOp) and isinstance(node.op, ast.Not):
        node = node.operand
    if isinstance(node, ast.Call):
        return _is_policy_engine_call(node, var_name)
    if not (
        isinstance(node, ast.Compare)
        and len(node.ops) == 1
        and isinstance(node.ops[0], (ast.Eq, ast.NotEq))
    ):
        return False
    left, right = node.left, node.comparators[0]
    for var_side, principal_side in ((left, right), (right, left)):
        if _contains_var_name(var_side, var_name) and is_principal_expr(principal_side):
            return True
    return False


def _classify_guard_test(test: ast.expr, var_name: str) -> str | None:
    if _is_principal_comparison(test, var_name):
        return "principal"
    if _is_membership_test(test, var_name):
        return "membership"
    if _is_prefix_test(test, var_name):
        return "prefix"
    if _is_containment_test(test, var_name):
        return "containment"
    return None


# ── one-hop aliasing & re-taint detection ─────────────────────────────────


def _collect_aliases_before(
    func_body: list[ast.stmt], guard_stmt: ast.stmt, var_name: str
) -> set[str]:
    """`var_name` itself, plus any variable directly assigned from it
    (`safe_x = x`, one hop, no transformation) on `guard_stmt`'s actual
    dominating path -- i.e. statements guaranteed to execute before the
    guard, not merely earlier in the function's flattened source order.

    Reuses `_collect_dominating_candidates` (the same recursive
    descend-only-into-the-taken-branch walk used to find the guard's own
    dominating statements relative to the sink) so an assignment sitting in
    one arm of an unrelated if/else -- with the other arm reassigning the
    same name to something disconnected from `var_name` -- is never treated
    as an unconditional alias. Confirmed bug otherwise: `if url in CACHE:
    checked = url` `else: checked = "http://example.com"` `if checked not
    in ALLOWED: return` would previously alias `checked` to `url`
    regardless of which branch actually ran, silently suppressing a real
    SSRF whenever `url` wasn't in `CACHE`."""
    aliases = {var_name}
    _, candidates = _collect_dominating_candidates(func_body, guard_stmt.lineno)
    for stmt in candidates:
        if (
            isinstance(stmt, ast.Assign)
            and len(stmt.targets) == 1
            and isinstance(stmt.targets[0], ast.Name)
            and isinstance(stmt.value, ast.Name)
            and stmt.value.id == var_name
        ):
            aliases.add(stmt.targets[0].id)
    return aliases


def _var_reassigned_between(
    func_body: list[ast.stmt], guard_stmt: ast.stmt, sink_line: int, var_name: str
) -> bool:
    """True if `var_name` (the exact tainted variable used at the sink,
    not an alias) is reassigned anywhere between the guard and the sink --
    re-tainting from a fresh source expression must invalidate the guard.
    Deliberately conservative: this scans the function's whole flattened
    order (not just the guard's true control-flow path), so a reassignment
    inside an unrelated sibling branch can also (over-cautiously) block
    suppression -- safe, since the failure mode is "finding stays at full
    confidence", never an incorrect suppression."""
    seen_guard = False
    for stmt in iter_body_statements(func_body):
        if not seen_guard:
            if stmt is guard_stmt:
                seen_guard = True
            continue
        s_line = stmt.lineno
        s_end = getattr(stmt, "end_lineno", None) or s_line
        if s_line <= sink_line <= s_end:
            break
        reassigns = (
            isinstance(stmt, ast.Assign)
            and any(isinstance(t, ast.Name) and t.id == var_name for t in stmt.targets)
        ) or (
            isinstance(stmt, (ast.AnnAssign, ast.AugAssign))
            and isinstance(stmt.target, ast.Name)
            and stmt.target.id == var_name
        )
        if reassigns:
            return True
    return False


# ── public entry points ────────────────────────────────────────────────────


def find_dominating_guard(tree: ast.AST, sink_line: int, var_name: str) -> str | None:
    """Return the guard-kind string ("membership"/"prefix"/"containment")
    if a dominating early-return guard protects `var_name` before
    `sink_line`, else None."""
    func = _find_enclosing_function(tree, sink_line)
    if func is None:
        return None

    found, candidates = _collect_dominating_candidates(func.body, sink_line)
    if not found:
        return None

    for stmt in candidates:
        if not isinstance(stmt, ast.If):
            continue
        if not _body_unconditionally_exits(stmt.body):
            continue
        aliases = _collect_aliases_before(func.body, stmt, var_name)
        kind = None
        for name in aliases:
            kind = _classify_guard_test(stmt.test, name)
            if kind:
                break
        if not kind:
            continue
        if _var_reassigned_between(func.body, stmt, sink_line, var_name):
            continue
        return kind
    return None


def _extract_var_from_sink_snippet(snippet: str) -> str | None:
    """The sink node's snippet is usually the *whole* sink call (e.g.
    `requests.get(url)`), so `_extract_root_var` alone would return the
    call's receiver (`requests`), not the tainted argument. Parse it as an
    expression and pull the first bare-name argument instead; fall back to
    `_extract_root_var` (reused from source_tracer, not reimplemented) for
    anything that isn't a simple call shape."""
    snippet = snippet.strip()
    try:
        parsed = ast.parse(snippet, mode="eval")
    except SyntaxError:
        return _extract_root_var(snippet)
    node = parsed.body
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        # A call's own root (`_extract_root_var` on the whole snippet would
        # return the receiver, e.g. "requests") is never the tainted
        # argument, so a call with no simple-name argument or keyword value
        # has no recoverable variable at all -- inline expressions like
        # `requests.get(request.args.get('url'))` correctly yield None
        # rather than a bogus, never-matching name.
        for arg in node.args:
            if isinstance(arg, ast.Name):
                return arg.id
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name):
                return kw.value.id
        return None
    return _extract_root_var(snippet)


def extract_sink_var_name(taint_flow: TaintFlow | None) -> str | None:
    """Recover the tainted variable name feeding the sink. Prefers the last
    `intermediate_vars` entry (the variable Opengrep's own dataflow trace
    recorded immediately before the sink -- e.g. `url` in `url =
    request.args.get(...)` ... `requests.get(url)`), since that is exactly
    the name a hand-written guard clause would reference. Falls back to
    parsing the sink snippet itself when there's no intermediate variable
    (a fully inline source-to-sink expression, which by construction has no
    name a guard clause could test, so this will usually still yield
    None)."""
    if taint_flow is None:
        return None
    if taint_flow.intermediate:
        candidate = taint_flow.intermediate[-1].snippet.strip()
        if _SIMPLE_IDENTIFIER_RE.fullmatch(candidate):
            return candidate
    if taint_flow.sink is None:
        return None
    return _extract_var_from_sink_snippet(taint_flow.sink.snippet)


def check_guard_suppression(tree: ast.AST, sink_line: int, taint_flow: TaintFlow | None) -> str | None:
    """Top-level entry point: extract the tainted variable from
    `taint_flow` and check for a dominating early-return guard on it before
    `sink_line` in `tree`. Returns the guard-kind string on a match, else
    None."""
    var_name = extract_sink_var_name(taint_flow)
    if not var_name:
        return None
    return find_dominating_guard(tree, sink_line, var_name)

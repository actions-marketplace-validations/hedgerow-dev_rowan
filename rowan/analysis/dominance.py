"""Shared lightweight dominance primitive (GitHub issue #124).

Extracted from `rowan/analysis/guard_clause.py` (originally written for
issue #160 / DEF-40's early-return guard fix) so it can be reused by any
pass that needs to know which statements unconditionally execute before a
given line on its *actual* control-flow path -- not merely "somewhere
earlier in the function, at any nesting depth."

`collect_dominating_candidates` recursively walks a statement block and
returns the statements that dominate `sink_line`: earlier siblings in the
block itself, plus (recursively) earlier siblings in whichever nested
branch actually leads to the sink. A sibling branch that does *not* lead to
the sink (the other arm of an if/else, or a loop body when the sink sits
after the loop) is never descended into, so a check living in a mutually
exclusive branch or an unrelated loop is correctly excluded.

This is deliberately NOT a full CFG/dominator tree -- it is a narrower,
cheaper approximation that is sound for the straight-line/if-else/loop/
with/try shapes this codebase's taint analysis cares about. Two consumers
as of this writing:

  - `guard_clause.py`'s early-return guard-clause post-filter (issue #160),
  - `cross_file.py`'s `_classify_path_sanitizer` and `enrichment.py`'s
    `_suppress_sanitizer_window` (issue #124), which require a sanitizer
    check to actually dominate the sink/return it's meant to protect,
    instead of merely existing somewhere in the function body or within a
    fixed proximity window of the finding.
"""

from __future__ import annotations

import ast


def find_enclosing_function(
    tree: ast.AST, line: int
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    """The innermost function definition whose span contains `line`."""
    best: ast.FunctionDef | ast.AsyncFunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            if node.lineno <= line <= end and (best is None or node.lineno > best.lineno):
                best = node
    return best


def collect_dominating_candidates(
    block: list[ast.stmt], sink_line: int
) -> tuple[bool, list[ast.stmt]]:
    """Recursively locate the statement containing `sink_line` inside
    `block` and return (found, candidates), where candidates are the
    statements that unconditionally execute before the sink on its actual
    control-flow path: earlier siblings in `block` itself, plus
    (recursively) earlier siblings in whichever nested branch actually
    leads to the sink.

    Deliberately NOT a full CFG/dominator tree -- but critically, a sibling
    branch that does *not* lead to the sink (the other arm of an if/else,
    or a loop body when the sink sits after the loop) is never descended
    into, so a guard living in a mutually exclusive branch or an unrelated
    loop is correctly excluded, even though this is a much cheaper check
    than real dominance.
    """
    candidates: list[ast.stmt] = []
    for stmt in block:
        s_line = stmt.lineno
        s_end = getattr(stmt, "end_lineno", None) or s_line
        if s_line <= sink_line <= s_end:
            nested: list[ast.stmt] = []
            if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
                found_b, cands_b = collect_dominating_candidates(stmt.body, sink_line)
                if found_b:
                    nested = cands_b
                else:
                    found_o, cands_o = collect_dominating_candidates(stmt.orelse, sink_line)
                    if found_o:
                        nested = cands_o
            elif isinstance(stmt, (ast.With, ast.AsyncWith)):
                _, nested = collect_dominating_candidates(stmt.body, sink_line)
            elif isinstance(stmt, ast.Try):
                for sub in (stmt.body, *(h.body for h in stmt.handlers), stmt.orelse, stmt.finalbody):
                    found_s, cands_s = collect_dominating_candidates(sub, sink_line)
                    if found_s:
                        nested = cands_s
                        break
            return True, candidates + nested
        candidates.append(stmt)
    return False, []

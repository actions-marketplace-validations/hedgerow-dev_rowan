"""Shared AST statement-flattening helper.

Extracted from `rowan/passes/cross_file.py` (GitHub issue #160) so both
`CrossFilePass` and `EnrichmentPass`'s guard-clause post-filter
(`rowan/analysis/guard_clause.py`) can reuse the exact same
execution-order flattening logic without duplicating it -- see issue #124
for the fuller dominator/CFG treatment this narrower logic will eventually
feed into.
"""

from __future__ import annotations

import ast
from collections.abc import Iterator

# `except*` (ast.TryStar) is Python 3.11+; the package supports 3.10.
_TRY_NODES = (ast.Try, ast.TryStar) if hasattr(ast, "TryStar") else (ast.Try,)


def iter_body_statements(stmts: list[ast.stmt]) -> Iterator[ast.stmt]:
    """Flatten a function body's statements in execution order, descending
    into control-flow blocks but not into nested function/class defs."""
    for stmt in stmts:
        yield stmt
        if isinstance(stmt, (ast.If, ast.For, ast.AsyncFor, ast.While)):
            yield from iter_body_statements(stmt.body)
            yield from iter_body_statements(stmt.orelse)
        elif isinstance(stmt, (ast.With, ast.AsyncWith)):
            yield from iter_body_statements(stmt.body)
        elif isinstance(stmt, ast.Match):
            for case in stmt.cases:
                yield from iter_body_statements(case.body)
        elif isinstance(stmt, _TRY_NODES):
            yield from iter_body_statements(stmt.body)
            for handler in stmt.handlers:
                yield from iter_body_statements(handler.body)
            yield from iter_body_statements(stmt.orelse)
            yield from iter_body_statements(stmt.finalbody)

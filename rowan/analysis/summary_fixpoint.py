"""Round-based function-summary fixpoint that skips unchanged functions.

The interprocedural AI passes re-analyzed every function in the repository
each round until no summary changed. On PyTorch (116k functions) that was 11
full rounds, although from round 3 on fewer than 500 summaries changed.

A function's summary depends only on the summaries of the callees it resolves.
So after the first round, only callers of a function whose summary changed can
change. This computes the same rounds with the same inputs as the full loop,
re-running just those callers, so the result is identical.
"""

from __future__ import annotations

import ast
from collections.abc import Callable, Hashable, Mapping
from typing import TypeVar

K = TypeVar("K", bound=Hashable)
S = TypeVar("S")


def solve_summaries(
    functions: Mapping[K, ast.AST],
    initial: Mapping[K, S],
    resolve: Callable[[ast.Call, K], K | None],
    analyze: Callable[[K, dict[K, S]], S],
) -> dict[K, S]:
    """Iterate ``analyze(key, summaries)`` to a fixpoint, one round at a time.

    ``analyze`` may read only the summaries of keys that ``resolve`` returns
    for calls inside ``functions[key]``. Each round sees only the previous
    round's summaries.
    """
    callers: dict[K, set[K]] = {key: set() for key in initial}
    for caller, node in functions.items():
        for call in ast.walk(node):
            if isinstance(call, ast.Call):
                callee = resolve(call, caller)
                if callee is not None:
                    callers[callee].add(caller)

    summaries = dict(initial)
    pending = set(summaries)
    for _ in range(len(summaries) + 1):
        updated = {key: analyze(key, summaries) for key in pending}
        changed = [key for key, summary in updated.items() if summary != summaries[key]]
        if not changed:
            break
        summaries.update(updated)
        pending = {caller for key in changed for caller in callers[key]}
    return summaries

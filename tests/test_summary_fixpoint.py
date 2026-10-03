"""solve_summaries must match the full-rescan fixpoint while skipping work."""

import ast

from rowan.analysis.summary_fixpoint import solve_summaries

SOURCE = """
def leaf(): return 1
def mid(): return leaf()
def top(): return mid()
def ping(): return pong()
def pong(): return ping() or leaf()
def alone(): return 0
"""


def _setup():
    tree = ast.parse(SOURCE)
    functions = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    def resolve(call, _key):
        name = call.func.id if isinstance(call.func, ast.Name) else None
        return name if name in functions else None

    # Summary: the set of functions reachable through calls, including the
    # "leaf" marker only when leaf is reachable. Monotone, needs several rounds.
    def analyze(key, summaries):
        out = {key} if key == "leaf" else set()
        for call in ast.walk(functions[key]):
            if isinstance(call, ast.Call) and (callee := resolve(call, key)):
                out |= {callee} | summaries[callee]
        return frozenset(out)

    return functions, resolve, analyze


def test_matches_full_rescan_fixpoint():
    functions, resolve, analyze = _setup()
    expected = {key: frozenset() for key in functions}
    while True:
        updated = {key: analyze(key, expected) for key in functions}
        if updated == expected:
            break
        expected = updated

    initial = {key: frozenset() for key in functions}
    assert solve_summaries(functions, initial, resolve, analyze) == expected


def test_reanalyzes_only_callers_of_changed_summaries():
    functions, resolve, analyze = _setup()
    calls: list[str] = []

    def counted(key, summaries):
        calls.append(key)
        return analyze(key, summaries)

    solve_summaries(functions, {key: frozenset() for key in functions}, resolve, counted)

    # Every function runs in round one; "alone" calls nothing, so never again.
    assert calls.count("alone") == 1
    assert calls.count("top") > 1

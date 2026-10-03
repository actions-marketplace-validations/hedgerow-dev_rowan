"""BFS-based fixpoint (#163, Phase C2): true hop distances, deterministic
shortest-chain selection, and no convergence cap.

Complements tests/test_cross_file_callgraph_gaps.py::TestLongChainResolvesCompletely
(the long-chain-no-cap regression) with the diamond/cycle/multi-file cases
called out in the plan.
"""

from __future__ import annotations

from pathlib import Path

from rowan.passes.cross_file import (
    _FunctionSig,
    _ImportGraph,
    _propagate_cross_file,
)


def _cf(findings):
    return [f for f in findings if f.engine == "crossfile"]


def test_three_file_chain_reports_true_hop_distance():
    # a() -> b() -> c() [sink]. a() reads a source; b() has no sink/source of
    # its own, it's a pure pass-through hop.
    funcs = [
        _FunctionSig(
            name="a", file="a.py", line=1, params=[], calls=[("b", None)],
            has_source=True,
        ),
        _FunctionSig(
            name="b", file="b.py", line=1, params=[], calls=[("c", None)],
        ),
        _FunctionSig(
            name="c", file="c.py", line=1, params=[], calls=[],
            has_sink=True, sink_detail="sink",
        ),
    ]
    import_graph = _ImportGraph()
    import_graph.name_to_def[("a.py", "b")] = ("b.py", "b")
    import_graph.name_to_def[("b.py", "c")] = ("c.py", "c")

    findings = _propagate_cross_file(funcs, import_graph, [], Path("."))
    cf = _cf(findings)

    # a() gets its own finding for the full 2-hop chain (a->b->c). b() also
    # gets one: a's source propagates onto b across the args-passing a->b
    # edge, and b's own call to c (the sink) is a 1-hop reach in its own
    # right -- both are genuine, independently-anchored findings, not
    # duplicates of each other (same as the pre-#163 sweep algorithm).
    a_findings = [f for f in cf if f.file_path == "a.py"]
    assert len(a_findings) == 1
    assert a_findings[0].metadata["hop_depth"] == 2
    assert len(a_findings[0].taint_flow.intermediate) == 1  # the b->c hop

    b_findings = [f for f in cf if f.file_path == "b.py"]
    assert len(b_findings) == 1
    assert b_findings[0].metadata["hop_depth"] == 1


def test_diamond_shortest_path_wins_and_is_deterministic():
    # m() has TWO paths to the sink: m->b->d (2 hops) and m->c->x->d
    # (3 hops). BFS must resolve m's own sink distance/chain via the
    # SHORTER path, not whichever happens to be visited first in an
    # unordered traversal -- and a() (a's single edge is to m, not to b/c
    # directly) must inherit that shortest chain in its own finding.
    funcs = [
        _FunctionSig(
            name="a", file="a.py", line=1, params=[], calls=[("m", None)],
            has_source=True,
        ),
        _FunctionSig(
            name="m", file="m.py", line=1, params=[],
            calls=[("b", None), ("c", None)],
        ),
        _FunctionSig(name="b", file="b.py", line=1, params=[], calls=[("d", None)]),
        _FunctionSig(name="c", file="c.py", line=1, params=[], calls=[("x", None)]),
        _FunctionSig(name="x", file="x.py", line=1, params=[], calls=[("d", None)]),
        _FunctionSig(
            name="d", file="d.py", line=1, params=[], calls=[],
            has_sink=True, sink_detail="sink",
        ),
    ]
    import_graph = _ImportGraph()
    import_graph.name_to_def[("a.py", "m")] = ("m.py", "m")
    import_graph.name_to_def[("m.py", "b")] = ("b.py", "b")
    import_graph.name_to_def[("m.py", "c")] = ("c.py", "c")
    import_graph.name_to_def[("b.py", "d")] = ("d.py", "d")
    import_graph.name_to_def[("c.py", "x")] = ("x.py", "x")
    import_graph.name_to_def[("x.py", "d")] = ("d.py", "d")

    run1 = _propagate_cross_file(funcs, import_graph, [], Path("."))
    run2 = _propagate_cross_file(funcs, import_graph, [], Path("."))

    cf1 = [f for f in _cf(run1) if f.file_path == "a.py"]
    assert len(cf1) == 1
    # m is 2 hops from the sink via b (not 3 via c->x) -> a's single edge to
    # m is depth=sink_dist[m]=2 -> hop_depth=3, chain = [m.py, b.py].
    assert cf1[0].metadata["hop_depth"] == 3
    assert [n.file_path for n in cf1[0].taint_flow.intermediate] == ["m.py", "b.py"]

    # Deterministic: identical findings (same hop_depth, same chain) across
    # repeated runs on the same graph.
    cf2 = [f for f in _cf(run2) if f.file_path == "a.py"]
    assert [(f.metadata["hop_depth"], [n.file_path for n in f.taint_flow.intermediate]) for f in cf1] == [
        (f.metadata["hop_depth"], [n.file_path for n in f.taint_flow.intermediate]) for f in cf2
    ]


def test_cycle_terminates_and_emits_once():
    # a() <-> b(), with c() (reachable off b) having the sink. A cycle must
    # not hang the BFS and must not duplicate the finding.
    funcs = [
        _FunctionSig(
            name="a", file="a.py", line=1, params=[], calls=[("b", None)],
            has_source=True,
        ),
        _FunctionSig(
            name="b", file="b.py", line=1, params=[],
            calls=[("a", None), ("c", None)],
        ),
        _FunctionSig(
            name="c", file="c.py", line=1, params=[], calls=[],
            has_sink=True, sink_detail="sink",
        ),
    ]
    import_graph = _ImportGraph()
    import_graph.name_to_def[("a.py", "b")] = ("b.py", "b")
    import_graph.name_to_def[("b.py", "a")] = ("a.py", "a")
    import_graph.name_to_def[("b.py", "c")] = ("c.py", "c")

    findings = _propagate_cross_file(funcs, import_graph, [], Path("."))
    cf = _cf(findings)

    a_findings = [f for f in cf if f.file_path == "a.py"]
    assert len(a_findings) == 1  # not duplicated by the cycle
    assert a_findings[0].metadata["hop_depth"] == 2  # a->b->c

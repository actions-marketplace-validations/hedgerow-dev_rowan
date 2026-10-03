"""Regression tests for cross-file call-graph resolution gaps.

Covers (shared between cross_file.py's Python engine and js_cross_file.py,
which reuses _propagate_cross_file/_resolve_callee_file unmodified):
- self.foo()/cls.foo()/this.foo() calls used to resolve to no file at all
  (module_to_file.get((file, "self")) never matches a real import alias),
  silently dropping the call edge -- a major false-negative source since
  most OOP code routes through instance methods.
- a.b.foo() (a chained/complex qualifier) used to fall through to "assume
  same-file", fabricating a phantom call edge whenever a same-named
  function happened to exist in the caller's file.
- _emit_cross_file_finding's dedup key omitted `direction`, so a "sink"
  finding and a "return" finding on the same caller->callee edge collided
  and only the first-checked direction survived.
- the old fixed 50-sweep fixpoint silently produced incomplete results on a
  large/cyclic call graph that didn't converge within max_depth, with no
  signal to the user that anything was truncated -- replaced (issue #163) by
  a BFS-based propagator that has no such cap and reports the true call-chain
  hop distance instead of a sweep index.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from rowan.passes.cross_file import (
    _UNRESOLVED_QUALIFIER,
    _emit_cross_file_finding,
    _extract_functions,
    _FunctionSig,
    _ImportGraph,
    _propagate_cross_file,
    _resolve_call_target,
    _resolve_callee_file,
)


def _call_node(src: str) -> ast.Call:
    return ast.parse(src).body[0].value


class TestResolveCallTargetQualifiers:
    def test_self_call(self):
        assert _resolve_call_target(_call_node("self.process(x)")) == ("process", "self")

    def test_cls_call(self):
        assert _resolve_call_target(_call_node("cls.build(x)")) == ("build", "cls")

    def test_bare_call_has_no_qualifier(self):
        assert _resolve_call_target(_call_node("process(x)")) == ("process", None)

    def test_imported_alias_call(self):
        assert _resolve_call_target(_call_node("mod.process(x)")) == ("process", "mod")

    def test_chained_attribute_call_is_unresolved_not_none(self):
        """a.b.foo() must be distinguishable from foo() -- collapsing both
        to module_qualifier=None let it be treated as same-file-safe."""
        name, qual = _resolve_call_target(_call_node("a.b.foo(x)"))
        assert name == "foo"
        assert qual == _UNRESOLVED_QUALIFIER

    def test_self_attr_chain_resolves_by_method_name(self):
        """DEF-35: self.db.query(...)/self.session.add(...) used to be
        dropped entirely (returned _UNRESOLVED_QUALIFIER, same as an
        arbitrary a.b.foo() chain), so no call-graph edge was ever created
        for ORM-style `self.<attr>.<method>()` calls. One level of
        attribute chaining rooted in self/cls/this now resolves the same
        way a bare self.<method>() call does."""
        assert _resolve_call_target(_call_node("self.db.query(x)")) == ("query", "self")
        assert _resolve_call_target(_call_node("self.session.add(x)")) == ("add", "self")

    def test_cls_attr_chain_resolves_by_method_name(self):
        assert _resolve_call_target(_call_node("cls.registry.build(x)")) == ("build", "cls")

    def test_this_attr_chain_resolves_by_method_name(self):
        """Shared with js_cross_file.py's this.foo() convention."""
        assert _resolve_call_target(_call_node("this.repo.save(x)")) == ("save", "this")

    def test_non_self_attr_chain_still_unresolved(self):
        """Only self/cls/this get the one-level fallback -- an ordinary
        instance variable (e.g. `account.session.add(x)`) gives no signal
        that "add" is even defined in this file, so it must stay
        _UNRESOLVED_QUALIFIER just like the plain a.b.foo() case above."""
        name, qual = _resolve_call_target(_call_node("account.session.add(x)"))
        assert name == "add"
        assert qual == _UNRESOLVED_QUALIFIER

    def test_two_levels_beyond_self_still_unresolved(self):
        """Only ONE level of chaining beyond self/cls/this is trusted --
        self.a.b.foo() (two levels) must not also get the fallback."""
        name, qual = _resolve_call_target(_call_node("self.a.b.foo(x)"))
        assert name == "foo"
        assert qual == _UNRESOLVED_QUALIFIER


class TestResolveCalleeFileSelfQualifiers:
    def test_self_resolves_to_caller_file(self):
        graph = _ImportGraph()
        assert _resolve_callee_file("handler.py", "process", "self", graph) == "handler.py"

    def test_cls_resolves_to_caller_file(self):
        graph = _ImportGraph()
        assert _resolve_callee_file("handler.py", "build", "cls", graph) == "handler.py"

    def test_this_resolves_to_caller_file(self):
        """Shared with js_cross_file.py, which emits ("this", propname) tuples."""
        graph = _ImportGraph()
        assert _resolve_callee_file("handler.js", "process", "this", graph) == "handler.js"

    def test_unresolved_qualifier_does_not_guess_same_file(self):
        """a.b.foo() must never fabricate a same-file edge, even if a
        same-named function happens to exist in the caller's file."""
        graph = _ImportGraph()
        assert _resolve_callee_file("caller.py", "foo", _UNRESOLVED_QUALIFIER, graph) is None

    def test_bare_call_still_resolves_to_caller_file(self):
        """Regression guard: a genuinely unqualified call with no matching
        import must keep resolving to the caller's own file."""
        graph = _ImportGraph()
        assert _resolve_callee_file("caller.py", "helper", None, graph) == "caller.py"


class TestSelfCallFixpointPropagation:
    """A same-file self.foo() hop must not break a longer cross-file chain."""

    def test_source_reaches_cross_file_sink_through_self_call(self):
        handler_path = "/proj/handler.py"
        sink_path = "/proj/sink_mod.py"

        import_graph = _ImportGraph()
        import_graph.name_to_def[(handler_path, "dangerous_write")] = (sink_path, "dangerous_write")

        funcs = [
            _FunctionSig(
                name="handle", file=handler_path, line=1, params=[],
                calls=[("process", "self")], has_source=True,
            ),
            _FunctionSig(
                name="process", file=handler_path, line=5, params=[],
                calls=[("dangerous_write", None)],
            ),
            _FunctionSig(
                name="dangerous_write", file=sink_path, line=1, params=[],
                calls=[], has_sink=True, sink_detail="pickle.loads",
            ),
        ]

        findings = _propagate_cross_file(funcs, import_graph, [], Path("/proj"))
        cf = [f for f in findings if f.engine == "crossfile"]
        assert len(cf) >= 1, "self.process() hop must not sever the source->sink chain"
        assert any(f.file_path == handler_path for f in cf)


class TestSelfAttrChainFixpointPropagation:
    """DEF-35: a self.<attr>.<method>() hop (e.g. self.db.query(...)) must
    not sever a cross-file chain either -- before the fix this call got no
    edge at all (_resolve_call_target returned _UNRESOLVED_QUALIFIER for
    any receiver beyond a bare Name), so a source reaching a sink only
    through such a call was invisible to propagation."""

    def test_self_attr_chain_call_gets_a_call_graph_edge(self):
        """The real bug, exercised through the actual extraction pipeline:
        before the fix, self.db.query(...) resolved to
        ("query", _UNRESOLVED_QUALIFIER) and _resolve_callee_file drops any
        edge for that qualifier -- so this call graph edge never existed at
        all, regardless of what it called into."""
        handler_path = "/proj/handler.py"
        src = (
            "class Handler:\n"
            "    def handle(self, request):\n"
            "        user_input = request.args.get('q')\n"
            "        return self.db.query(user_input)\n"
        )
        tree = ast.parse(src)
        funcs = _extract_functions(handler_path, tree, def_nodes={})
        handle_sig = next(f for f in funcs if f.name == "handle")
        assert any(c[:3] == ("query", "self", True) for c in handle_sig.calls)

    def test_source_reaches_sink_through_self_attr_chain_call(self):
        """The self.<attr>.<method>() hop only ever resolves to a same-file
        callee (module_qual in _SELF_QUALIFIERS -> name_to_def keyed on the
        *caller's own* file, just like a bare self.foo() call) -- so on its
        own it can never be the hop a crossfile finding is emitted on
        (_emit_cross_file_finding skips same-file caller/callee pairs).
        What it must not do is sever a LONGER chain that genuinely does
        cross a file boundary further down: handle() [source, file1] ->
        self.db.execute(...) [same-file self-attr hop] -> utils.write(...)
        [file2, sink]. Before the DEF-35 fix, the self-attr hop got no call
        graph edge at all (_resolve_call_target returned
        _UNRESOLVED_QUALIFIER for any receiver beyond a bare Name), which
        would have severed this chain at the very first hop regardless of
        what came after it."""
        handler_path = "/proj/handler.py"
        utils_path = "/proj/utils.py"
        import_graph = _ImportGraph()
        # self.db.execute(...) -> ("execute", "self"): resolved same-file,
        # by name (same mechanism a bare self.foo() call already uses).
        import_graph.name_to_def[(handler_path, "execute")] = (handler_path, "execute")
        # execute() -> utils.write(...): resolved by import alias, a
        # genuine cross-file edge.
        import_graph.module_to_file[(handler_path, "utils")] = utils_path

        funcs = [
            _FunctionSig(
                name="handle", file=handler_path, line=1, params=[],
                calls=[("execute", "self")], has_source=True,
            ),
            _FunctionSig(
                name="execute", file=handler_path, line=5, params=[],
                calls=[("write", "utils")],
            ),
            _FunctionSig(
                name="write", file=utils_path, line=1, params=[],
                calls=[], has_sink=True, sink_detail="raw SQL execute",
            ),
        ]

        findings = _propagate_cross_file(funcs, import_graph, [], Path("/proj"))
        cf = [f for f in findings if f.engine == "crossfile"]
        assert len(cf) >= 1, "self.db.execute() hop must not sever the source->sink chain"
        assert any(f.file_path == handler_path for f in cf)


class TestDedupPreservesDirection:
    def test_sink_and_return_findings_on_same_edge_both_kept(self):
        findings: list = []
        seen: set = set()

        caller = _FunctionSig(name="caller", file="a.py", line=1, params=[], calls=[])
        callee = _FunctionSig(
            name="callee", file="b.py", line=1, params=[], calls=[],
            has_sink=True, sink_detail="test",
        )

        _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "sink")
        _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "return")

        assert len(findings) == 2
        directions = {f.metadata["direction"] for f in findings}
        assert directions == {"sink", "return"}

    def test_same_direction_still_deduped(self):
        findings: list = []
        seen: set = set()

        caller = _FunctionSig(name="caller", file="a.py", line=1, params=[], calls=[])
        callee = _FunctionSig(
            name="callee", file="b.py", line=1, params=[], calls=[],
            has_sink=True, sink_detail="test",
        )

        _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "sink")
        _emit_cross_file_finding(findings, seen, caller, callee, ("b.py", "callee"), 0, "sink")

        assert len(findings) == 1


class TestLongChainResolvesCompletely:
    """Issue #163: the old fixed 50-sweep fixpoint silently truncated any
    chain longer than 50 hops (logging a "did not converge" warning instead
    of completing). The BFS-based propagator has no such cap -- a plain BFS
    over a finite graph always terminates -- so a chain far longer than the
    old limit must now resolve completely, with the reported hop_depth equal
    to the REAL call-chain distance (not a sweep index)."""

    def test_chain_longer_than_old_cap_resolves_with_accurate_hop_depth(self, caplog):
        chain_len = 60  # longer than the old max_depth=50
        funcs = [
            _FunctionSig(
                name="entry", file="f0.py", line=1, params=[],
                calls=[("step_1", None)], has_source=True,
            ),
        ]
        for i in range(1, chain_len):
            funcs.append(
                _FunctionSig(
                    name=f"step_{i}", file=f"f{i}.py", line=1, params=[],
                    calls=[(f"step_{i + 1}", None)],
                )
            )
        funcs.append(
            _FunctionSig(
                name=f"step_{chain_len}", file=f"f{chain_len}.py", line=1,
                params=[], calls=[], has_sink=True, sink_detail="sink",
            )
        )
        import_graph = _ImportGraph()
        import_graph.name_to_def[("f0.py", "step_1")] = ("f1.py", "step_1")
        for i in range(1, chain_len):
            import_graph.name_to_def[(f"f{i}.py", f"step_{i + 1}")] = (
                f"f{i + 1}.py", f"step_{i + 1}"
            )

        with caplog.at_level(logging.WARNING):
            findings = _propagate_cross_file(funcs, import_graph, [], Path("."))

        assert not any("did not converge" in r.message for r in caplog.records)
        # entry() is chain_len hops away from the function that actually has
        # the sink (step_1 is 1 hop from the sink-bearing step_60, ...,
        # entry->step_1 is the outermost hop) -- the finding pinned at
        # entry() must report the full real distance, not a truncated one.
        cf = [f for f in findings if f.engine == "crossfile"]
        assert any(f.file_path == "f0.py" for f in cf), [f.file_path for f in cf]
        entry_finding = next(f for f in cf if f.file_path == "f0.py")
        assert entry_finding.metadata["hop_depth"] == chain_len

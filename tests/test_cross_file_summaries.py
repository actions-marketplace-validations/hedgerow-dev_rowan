"""Per-parameter procedure summaries + argument-to-parameter threading (#119,
Phase C3): sink_params/return_params, edge_bindings, and the precision they
add over the old "any argument passes" gate.
"""

from __future__ import annotations

import ast
from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanConfig, ScanContext
from rowan.passes.cross_file import (
    CrossFilePass,
    _summarize_params,
)


def _write(root: Path, rel: str, body: str) -> str:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(body)
    return str(p.resolve())


def _run(root: Path, findings: list[Finding]) -> list[Finding]:
    ctx = ScanContext(
        target_path=root, config=ScanConfig(target=root), result=ScanResult(findings=findings)
    )
    return CrossFilePass().run(ctx).findings


def _cf(findings: list[Finding]) -> list[Finding]:
    return [f for f in findings if f.engine == "crossfile"]


def _sink_finding(file_str: str, line: int, rule_id: str = "NS-CMDI-001") -> Finding:
    return Finding(
        rule_id=rule_id,
        message="command injection",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path=file_str,
        start_line=line,
        engine="neuroscan",
    )


def _line_of(file_str: str, marker: str) -> int:
    for i, ln in enumerate(Path(file_str).read_text().splitlines(), start=1):
        if marker in ln:
            return i
    raise AssertionError(f"{marker!r} not found in {file_str}")


_SINK_ON_P1 = (
    "def sink_on_p1(safe, cmd):\n"
    "    import os\n"
    "    os.system(cmd)\n"
)


def test_taint_into_safe_slot_produces_no_finding(tmp_path):
    sink_file = _write(tmp_path, "sink.py", _SINK_ON_P1)
    _write(
        tmp_path, "handler.py",
        (
            "from sink import sink_on_p1\n"
            "from flask import request\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    sink_on_p1(user_input, 'ls')\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(sink_file, _line_of(sink_file, "os.system"))])
    cf = [f for f in _cf(findings) if f.metadata.get("callee_name") == "sink_on_p1"]
    assert cf == [], f"taint only reached the SAFE parameter, must not fire: {[f.message for f in cf]}"


def test_taint_into_dangerous_slot_produces_finding(tmp_path):
    sink_file = _write(tmp_path, "sink.py", _SINK_ON_P1)
    _write(
        tmp_path, "handler.py",
        (
            "from sink import sink_on_p1\n"
            "from flask import request\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    sink_on_p1('ls', user_input)\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(sink_file, _line_of(sink_file, "os.system"))])
    cf = [f for f in _cf(findings) if f.metadata.get("callee_name") == "sink_on_p1"]
    assert cf, "taint reached the DANGEROUS parameter, must fire"


def test_keyword_binding_discriminates_the_same_way(tmp_path):
    sink_file = _write(tmp_path, "sink.py", _SINK_ON_P1)
    _write(
        tmp_path, "handler.py",
        (
            "from sink import sink_on_p1\n"
            "from flask import request\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    sink_on_p1(cmd=user_input, safe='x')\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(sink_file, _line_of(sink_file, "os.system"))])
    cf = [f for f in _cf(findings) if f.metadata.get("callee_name") == "sink_on_p1"]
    assert cf, "keyword arg cmd=user_input binds to the dangerous parameter, must fire"


def test_sanitized_param_suppresses_finding(tmp_path):
    sink_file = _write(
        tmp_path, "sink.py",
        (
            "def f(p):\n"
            "    import os, shlex\n"
            "    q = shlex.quote(p)\n"
            "    os.system(q)\n"
        ),
    )
    _write(
        tmp_path, "handler.py",
        (
            "from sink import f\n"
            "from flask import request\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    f(user_input)\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(sink_file, _line_of(sink_file, "os.system"))])
    cf = [x for x in _cf(findings) if x.metadata.get("callee_name") == "f"]
    assert cf == [], f"p is sanitized via shlex.quote before reaching the sink: {[x.message for x in cf]}"


def test_return_params_threads_passthru_to_callers_sink(tmp_path):
    _write(tmp_path, "util.py", "def passthru(p):\n    return p\n")
    handler_file = _write(
        tmp_path, "handler.py",
        (
            "from util import passthru\n"
            "from flask import request\n"
            "import os\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    cmd = passthru(user_input)\n"
            "    os.system(cmd)\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(handler_file, _line_of(handler_file, "os.system"))])
    cf = [f for f in _cf(findings) if f.metadata.get("callee_name") == "passthru"]
    assert cf, "passthru(user_input)'s return value flows straight into handle's own sink"
    assert cf[0].metadata["direction"] == "return"


def test_return_params_direct_construction():
    """Unit-level: _summarize_params attributes `return p` to parameter 0."""
    tree = ast.parse("def passthru(p):\n    return p\n")
    fn = tree.body[0]
    sink_params, return_params = _summarize_params(fn, 0)
    assert return_params == frozenset({0})
    assert sink_params == frozenset()


def test_backward_compat_hand_built_sigs_use_old_any_arg_gate():
    """Every existing direct-call unit test builds `_FunctionSig`s by hand
    (2-/3-/4-tuple `calls`, sink_params/return_params left at their None
    default) and calls `_propagate_cross_file` without going through
    `CrossFilePass.run()` at all -- so `_compute_param_summaries` never runs,
    and the old any-argument gate must still apply unchanged. This is the
    same scenario as tests/test_cross_file.py::test_propagate_cross_file_fixpoint,
    re-asserted here as the explicit #119 backward-compat check."""
    from rowan.passes.cross_file import _FunctionSig, _ImportGraph, _propagate_cross_file

    funcs = [
        _FunctionSig(
            name="handler", file="a.py", line=1, params=[], calls=[("helper", None)],
            has_source=True,
        ),
        _FunctionSig(
            name="helper", file="b.py", line=1, params=["x"], calls=[],
            has_sink=True, sink_detail="sink",
            # sink_params deliberately left at the default None.
        ),
    ]
    import_graph = _ImportGraph()
    import_graph.name_to_def[("a.py", "helper")] = ("b.py", "helper")

    findings = _propagate_cross_file(funcs, import_graph, [], Path("."))
    cf = [f for f in findings if f.engine == "crossfile"]
    assert len(cf) == 1, "sink_params=None must fall back to the old any-argument gate"


def test_scalar_reducing_return_does_not_propagate_taint():
    """A parameter that appears in the return only inside a content-independent
    scalar reducer (len/int/bool/hash/...) is NOT a return_param -- the value
    returned is a count/number/type, not the argument's injectable content.
    Regression for cross-file return-taint FPs like ragflow's
    num_tokens_from_string(): `return len(encoding.encode(s))`."""
    def ret_params(src: str) -> set[int]:
        fn = ast.parse(src).body[0]
        _sink, rp = _summarize_params(fn, 0)
        return set(rp)

    # Reduced to a scalar -> no propagation.
    assert ret_params("def f(s):\n    return len(enc.encode(s))") == set()
    assert ret_params("def f(s):\n    return int(s)") == set()
    assert ret_params("def f(s):\n    return bool(s)") == set()
    # Genuine passthrough / content-preserving transforms -> still propagate.
    assert ret_params("def f(s):\n    return s") == {0}
    assert ret_params("def f(s):\n    return str(s)") == {0}
    # A tuple that merely CONTAINS a reducer still propagates the raw part.
    assert ret_params("def f(s):\n    return len(s), s") == {0}


def test_cross_file_log_sink_emitted_medium_not_high():
    """A cross-file taint whose sink is a log statement (CWE-117 log forging) is
    real but log poisoning, not RCE, so it is emitted MEDIUM. Any other sink CWE
    stays HIGH. Regression: letta's rest_api routers had 7 HIGH cross-file
    findings that were all user-input-to-log-statement flows."""
    from rowan.core.findings import Severity
    from rowan.passes.cross_file import _emit_cross_file_finding, _FunctionSig

    def emit(sink_cwe):
        caller = _FunctionSig(name="handler", file="a.py", line=10, params=[], calls=[], end_line=20)
        callee = _FunctionSig(name="log_it", file="b.py", line=5, params=[], calls=[], end_line=8,
                              has_sink=True, sink_detail="flows to a log statement",
                              sink_cwe=sink_cwe, sink_line=6)
        out: list = []
        _emit_cross_file_finding(out, set(), caller, callee, ("b.py", "log_it"), 0, "sink", call_line=12)
        return out[0].severity

    assert emit([117]) == Severity.MEDIUM, "log forging cross-file sink must be MEDIUM"
    assert emit([89]) == Severity.HIGH, "SQLi cross-file sink stays HIGH"
    assert emit([]) == Severity.HIGH, "unclassified cross-file sink stays HIGH"

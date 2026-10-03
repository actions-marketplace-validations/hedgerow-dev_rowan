"""Annotation-based sanitization (#121, Phase D): a parameter the author
annotated with a taint-incapable scalar type (int/float/bool/complex, plus
their Optional/`| None` forms) is treated as sanitized at the parameter
boundary and never carries taint into a cross-file sink.
"""

from __future__ import annotations

import ast
from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanConfig, ScanContext
from rowan.passes.cross_file import (
    CrossFilePass,
    _scalar_annotated_params,
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


def _cf_for(findings: list[Finding], callee: str) -> list[Finding]:
    return [
        f for f in findings
        if f.engine == "crossfile" and f.metadata.get("callee_name") == callee
    ]


def _sink_finding(file_str: str, line: int) -> Finding:
    return Finding(
        rule_id="NS-CMDI-001", message="command injection", severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION, file_path=file_str, start_line=line,
        engine="neuroscan",
    )


def _os_system_line(file_str: str) -> int:
    for i, ln in enumerate(Path(file_str).read_text().splitlines(), start=1):
        if "os.system(" in ln:
            return i
    raise AssertionError("no os.system(")


# ---- unit ---------------------------------------------------------------- #

def test_scalar_annotated_params_recognizes_forms():
    src = (
        "def f(a: int, b: float, c: bool, d: complex,\n"
        "      e: Optional[int], g: int | None, h: str, i, j: bytes):\n"
        "    pass\n"
    )
    fn = ast.parse(src).body[0]
    safe = _scalar_annotated_params(fn)
    assert safe == {"a", "b", "c", "d", "e", "g"}
    # str / unannotated / bytes are NOT safe
    assert "h" not in safe and "i" not in safe and "j" not in safe


def test_int_param_excluded_from_sink_params():
    src = "def f(cmd: int):\n    import os\n    os.system(cmd)\n"
    fn = ast.parse(src).body[0]
    sl = next(
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "system"
    )
    sink_params, _ = _summarize_params(fn, sl)
    assert sink_params == frozenset()


def test_str_param_still_in_sink_params():
    src = "def f(cmd: str):\n    import os\n    os.system(cmd)\n"
    fn = ast.parse(src).body[0]
    sl = next(
        n.lineno for n in ast.walk(fn)
        if isinstance(n, ast.Call) and getattr(n.func, "attr", None) == "system"
    )
    sink_params, _ = _summarize_params(fn, sl)
    assert sink_params == frozenset({0})


# ---- end-to-end ---------------------------------------------------------- #

def test_int_annotated_sink_param_suppresses_cross_file_finding(tmp_path):
    sink = _write(tmp_path, "sink.py", "def run(n: int):\n    import os\n    os.system(n)\n")
    _write(
        tmp_path, "handler.py",
        (
            "from sink import run\n"
            "from flask import request\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    run(user_input)\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(sink, _os_system_line(sink))])
    assert _cf_for(findings, "run") == [], "int-annotated sink param can't carry the payload"


def test_str_annotated_sink_param_still_fires(tmp_path):
    """Positive control: same shape but a `: str` annotation -- must still fire."""
    sink = _write(tmp_path, "sink.py", "def run(n: str):\n    import os\n    os.system(n)\n")
    _write(
        tmp_path, "handler.py",
        (
            "from sink import run\n"
            "from flask import request\n"
            "def handle():\n"
            "    user_input = request.args.get('x')\n"
            "    run(user_input)\n"
        ),
    )
    findings = _run(tmp_path, [_sink_finding(sink, _os_system_line(sink))])
    assert _cf_for(findings, "run"), "str-annotated sink param must still be flagged"

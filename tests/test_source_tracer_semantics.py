"""Source tracer semantics (BACKLOG CN-03: TE-12, TE-13, TE-14): taint is a
max over inputs, and lookups stay inside the enclosing function."""

from __future__ import annotations

from pathlib import Path

from rowan.analysis.source_tracer import trace_source

_MIXED = """from flask import request

BASE = "/usr/bin"


def h():
    cmd = "ls " + request.args["d"]
    run(cmd)
    cmd2 = f"{BASE} {request.args['d']}"
    run(cmd2)
    cmd3 = request.args["d"] + " --safe"
    run(cmd3)
"""

_SCOPED = """def safe():
    name = "constant"
    return name


def handler(name):
    return name


def other():
    name = "again"
    return name
"""


def _write(tmp_path: Path, src: str) -> str:
    p = tmp_path / "t.py"
    p.write_text(src, encoding="utf-8")
    return str(p)


def test_binop_takes_the_tainted_side(tmp_path):
    path = _write(tmp_path, _MIXED)
    assert trace_source(path, "cmd", 8).label == "http_input"
    assert trace_source(path, "cmd3", 12).label == "http_input"


def test_fstring_takes_the_highest_taint_part(tmp_path):
    path = _write(tmp_path, _MIXED)
    assert trace_source(path, "cmd2", 10).label == "http_input"


def test_lookup_stays_inside_the_enclosing_function(tmp_path):
    path = _write(tmp_path, _SCOPED)
    origin = trace_source(path, "name", 7)
    assert origin.label == "function_param", origin
    assert trace_source(path, "name", 3).label == "constant_literal"


def test_lookup_does_not_descend_into_nested_function(tmp_path):
    path = _write(
        tmp_path,
        "from flask import request\n\n"
        "def handler(name):\n"
        "    def inner():\n"
        "        name = request.args['name']\n"
        "        return name\n"
        "    return name\n",
    )

    origin = trace_source(path, "name", 7)

    assert origin.label == "function_param", origin

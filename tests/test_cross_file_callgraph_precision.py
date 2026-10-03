"""Cross-file call-graph precision regressions (BACKLOG XF-01, XF-02, XF-04, XF-05).

Each test seeds the regex sink finding the taint pass would have produced and
asserts what CrossFilePass emits for a caller that reads `request.args`.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import CrossFilePass

_HANDLER_HEAD = "from flask import request\n"


def _project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="rowan_cf_precision_"))
    for name, content in files.items():
        (root / name).write_text(content, encoding="utf-8")
    return root


def _cmdi(
    path: Path,
    line: int,
    rule_id: str = "NS-CMDI-002",
    message: str = "subprocess with shell=True.",
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=message,
        severity=Severity.MEDIUM,
        category=Category.COMMAND_INJECTION,
        file_path=str(path.resolve()),
        start_line=line,
        engine="opengrep",
    )


def _cf_sinks(root: Path, seeds: list[Finding]) -> list[Finding]:
    ctx = ScanContext(
        target_path=root, config=ScanConfig(target=root), result=ScanResult(findings=seeds)
    )
    return [f for f in CrossFilePass().run(ctx).findings if f.rule_id == "CF-SINK-001"]


def test_multiline_sink_call_keeps_sink_params():
    # XF-01: a kwarg-line regex hit replaced the call-head line, so no Call
    # was found at sink_line and sink_params came back empty.
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + "from c import run_it\n\ndef handler():\n    q = request.args.get('q')\n    run_it(q)\n",
            "c.py": "import subprocess\n\ndef run_it(cmd):\n    subprocess.run(\n        cmd,\n        shell=True,\n    )\n",
        }
    )
    c = root / "c.py"
    seeds = [
        _cmdi(c, 4),
        _cmdi(c, 4, "NS-INJECT-003"),
        _cmdi(c, 6, "ns-aiml-076", "Presence signal"),
    ]
    cf = _cf_sinks(root, seeds)
    assert len(cf) == 1, [f.message for f in cf]
    assert cf[0].file_path.endswith("a.py") and cf[0].start_line == 6
    assert cf[0].taint_flow.sink.line == 4


def test_keyword_only_and_positional_only_params_reach_sink():
    # XF-05: `def run(*, cmd)` and `def run(cmd, /)` had no indexed params.
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + "from c import run_kw, run_pos, run_plain\n\ndef handler():\n    q = request.args.get('q')\n    run_kw(cmd=q)\n    run_pos(q)\n    run_plain(q)\n",
            "c.py": (
                "import subprocess\n\n"
                "def run_kw(*, cmd):\n    subprocess.run(cmd, shell=True)\n\n"
                "def run_pos(cmd, /):\n    subprocess.run(cmd, shell=True)\n\n"
                "def run_plain(cmd):\n    subprocess.run(cmd, shell=True)\n"
            ),
        }
    )
    c = root / "c.py"
    cf = _cf_sinks(root, [_cmdi(c, 4), _cmdi(c, 7), _cmdi(c, 10)])
    assert sorted(f.start_line for f in cf) == [6, 7, 8]


def test_aliased_from_import_resolves_to_target_name():
    # XF-04: `from c import run_it as go` keyed the callee as `go`.
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + "from c import run_it as go\n\ndef handler():\n    q = request.args.get('q')\n    go(q)\n",
            "c.py": "import subprocess\n\ndef run_it(cmd):\n    subprocess.run(cmd, shell=True)\n",
        }
    )
    cf = _cf_sinks(root, [_cmdi(root / "c.py", 4)])
    assert [f.start_line for f in cf] == [6]


_SHELL_THEN_SAFE = (
    "import subprocess\n\n"
    "class Shell:\n    def run(self, cmd):\n        subprocess.run(cmd, shell=True)\n\n"
    "class Safe:\n    def run(self, name):\n        return len(name)\n"
)


@pytest.mark.parametrize("call", ["s = Shell()\n    s.run(q)", "Shell().run(q)"])
def test_same_named_method_after_sink_method_does_not_mask_it(call):
    # XF-02: `(file, name)` was last-definition-wins, so Safe.run hid Shell.run.
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + f"from c import Shell\n\ndef handler():\n    q = request.args.get('q')\n    {call}\n",
            "c.py": _SHELL_THEN_SAFE,
        }
    )
    cf = _cf_sinks(root, [_cmdi(root / "c.py", 5)])
    assert len(cf) == 1, [f.message for f in cf]
    assert cf[0].taint_flow.sink.line == 5


def test_benign_same_named_method_is_not_attributed_to_sink_method():
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + "from c import Safe\n\ndef handler():\n    q = request.args.get('q')\n    Safe().run(q)\n",
            "c.py": _SHELL_THEN_SAFE,
        }
    )
    assert _cf_sinks(root, [_cmdi(root / "c.py", 5)]) == []


@pytest.mark.skipif(
    not __import__(
        "rowan.passes.js_cross_file", fromlist=["TREE_SITTER_AVAILABLE"]
    ).TREE_SITTER_AVAILABLE,
    reason="tree-sitter not installed",
)
def test_js_default_import_resolves_to_default_export():
    # XF-04 (JS half): `import runner from './shell.js'` was keyed as "default".
    from rowan.passes.js_cross_file import JSCrossFilePass

    root = _project(
        {
            "routes.js": "import runner from './shell.js';\napp.get('/x', (req, res) => {\n  const q = req.query.q;\n  runner(q);\n});\n",
            "shell.js": "export default function runShell(cmd) {\n  eval(cmd);\n}\n",
        }
    )
    seed = Finding(
        rule_id="JS-INJECT-001",
        message="eval sink",
        severity=Severity.HIGH,
        category=Category.INJECTION,
        file_path=str((root / "shell.js").resolve()),
        start_line=2,
        engine="opengrep",
    )
    ctx = ScanContext(
        target_path=root, config=ScanConfig(target=root), result=ScanResult(findings=[seed])
    )
    cf = [f for f in JSCrossFilePass().run(ctx).findings if f.rule_id == "CF-SINK-001"]
    assert len(cf) == 1, [f.message for f in cf]


_RELAY_CHAIN = {
    "b.py": "from c import run_it\n\ndef relay(x):\n    run_it(x)\n",
    "c.py": "import subprocess\n\ndef run_it(cmd):\n    subprocess.run(cmd, shell=True)\n",
}


def test_constant_argument_does_not_seed_source():
    # XF-06: `relay("constant")` propagated source status through an edge
    # carrying no tainted argument; both handler and relay were reported.
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + "from b import relay\n\ndef handler():\n    q = request.args.get('q')\n    relay('constant')\n    return q\n",
            **_RELAY_CHAIN,
        }
    )
    assert _cf_sinks(root, [_cmdi(root / "c.py", 4)]) == []


def test_tainted_argument_seeds_source_through_relay():
    root = _project(
        {
            "a.py": _HANDLER_HEAD
            + "from b import relay\n\ndef handler():\n    q = request.args.get('q')\n    relay(q)\n    return q\n",
            **_RELAY_CHAIN,
        }
    )
    cf = _cf_sinks(root, [_cmdi(root / "c.py", 4)])
    assert ("a.py", 6) in {(f.file_path.rsplit("/", 1)[1], f.start_line) for f in cf}


class TestLooksSanitizedScope:
    """BACKLOG XF-03: `_looks_sanitized` searched the registry regexes over the
    whole unparsed call, so `int(` matched inside `hint("x")` and `print(`."""

    @staticmethod
    def _sink_params(body: str) -> frozenset:
        import ast

        from rowan.passes.cross_file import _summarize_params

        src = (
            "import subprocess\n\ndef run_it(cmd):\n"
            + body
            + "    subprocess.run(full, shell=True)\n"
        )
        node = ast.parse(src).body[1]
        sink_line = src.count("\n")
        return _summarize_params(node, sink_line)[0]

    def test_sanitizer_name_inside_argument_does_not_clear_taint(self):
        assert self._sink_params('    full = wrap(cmd, hint("x"))\n') == frozenset({0})
        assert self._sink_params("    full = print(cmd)\n") == frozenset({0})

    def test_real_sanitizer_call_still_clears_taint(self):
        assert self._sink_params("    full = int(cmd)\n") == frozenset()
        assert self._sink_params("    full = shlex.quote(cmd)\n") == frozenset()

    def test_constant_keyword_sanitizer_still_recognised(self):
        assert self._sink_params("    full = torch.load(cmd, weights_only=True)\n") == frozenset()

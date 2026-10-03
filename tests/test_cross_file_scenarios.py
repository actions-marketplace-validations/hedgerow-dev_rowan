"""Cross-file taint propagation scenario tests.

Tests realistic multi-file Python projects to verify the CrossFilePass
correctly propagates taint across file boundaries.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.base import ScanContext
from rowan.passes.cross_file import CrossFilePass


def _make_project(files: dict[str, str]) -> Path:
    tmpdir = tempfile.mkdtemp(prefix="rowan_cf_scenario_")
    root = Path(tmpdir)
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _run_cross_file(root: Path, findings: list[Finding] | None = None) -> ScanResult:
    config = ScanConfig(target=root)
    ctx = ScanContext(
        target_path=root,
        config=config,
        result=ScanResult(findings=findings or []),
    )
    return CrossFilePass().run(ctx)


class TestTwoFileDirectCall:
    """A calls B, B has a sink, A has a source."""

    def test_source_to_sink_across_files(self):
        root = _make_project({
            "handler.py": (
                "from processor import process\n"
                "def handle(request):\n"
                "    data = request.args.get('input')\n"
                "    process(data)\n"
            ),
            "processor.py": (
                "import pickle\n"
                "def process(raw):\n"
                "    return pickle.loads(raw)\n"
            ),
        })
        handler_path = str((root / "handler.py").resolve())
        processor_path = str((root / "processor.py").resolve())

        seed_findings = [
            Finding(
                rule_id="TNT-DESER-001",
                message="pickle.loads on tainted data",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path=processor_path,
                start_line=3,
                engine="opengrep",
                taint_flow=TaintFlow(
                    source=TaintNode(file_path=processor_path, line=2),
                    sink=TaintNode(file_path=processor_path, line=3),
                ),
            ),
            Finding(
                rule_id="NS-DESER-001",
                message="pickle.loads()",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path=processor_path,
                start_line=3,
                engine="neuroscan",
            ),
            Finding(
                rule_id="TNT-SSRF-001",
                message="user input source",
                severity=Severity.MEDIUM,
                category=Category.SSRF,
                file_path=handler_path,
                start_line=3,
                engine="opengrep",
                taint_flow=TaintFlow(
                    source=TaintNode(file_path=handler_path, line=3),
                    sink=TaintNode(file_path=handler_path, line=4),
                ),
            ),
        ]

        result = _run_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        assert len(cf) >= 1, "Should emit cross-file finding when source calls sink across files"
        assert any("handle" in f.message for f in cf)


class TestThreeFileChain:
    """A -> B -> C transitive chain."""

    def test_transitive_taint_propagation(self):
        root = _make_project({
            "api.py": (
                "from middleware import transform\n"
                "def endpoint(request):\n"
                "    data = request.json.get('payload')\n"
                "    transform(data)\n"
            ),
            "middleware.py": (
                "from executor import run_cmd\n"
                "def transform(payload):\n"
                "    run_cmd(payload)\n"
            ),
            "executor.py": (
                "import os\n"
                "def run_cmd(cmd):\n"
                "    os.system(cmd)\n"
            ),
        })
        api_path = str((root / "api.py").resolve())
        executor_path = str((root / "executor.py").resolve())

        seed_findings = [
            Finding(
                rule_id="NS-INJECT-002",
                message="os.system() command injection",
                severity=Severity.HIGH,
                category=Category.COMMAND_INJECTION,
                file_path=executor_path,
                start_line=3,
                engine="neuroscan",
            ),
            Finding(
                rule_id="TNT-CMDI-001",
                message="user input flows to os.system",
                severity=Severity.HIGH,
                category=Category.COMMAND_INJECTION,
                file_path=api_path,
                start_line=3,
                engine="opengrep",
                taint_flow=TaintFlow(
                    source=TaintNode(file_path=api_path, line=3),
                    sink=TaintNode(file_path=api_path, line=4),
                ),
            ),
        ]

        result = _run_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        assert len(cf) >= 1, "Should propagate transitively across 3 files"


class TestPropagatorChain:
    """Download -> decode -> load chain using known propagators."""

    def test_propagator_marks_detected(self):
        """Was xfail(strict=False) -- now genuinely passes as a side effect of
        #119's return_params: load_remote_model's own `url` parameter flows
        into download() (a known propagator), whose return_params now
        correctly attributes its returned value back to `url`; the edge
        binding into load_remote_model's own pickle.loads sink completes the
        chain. See `_FunctionSig.return_params`'s docstring for the
        single-hop/direct scoping that makes this composable across the
        download -> load_remote_model boundary without a full multi-hop
        interprocedural summary."""
        root = _make_project({
            "downloader.py": (
                "import requests\n"
                "def download(url):\n"
                "    resp = requests.get(url)\n"
                "    return resp.content\n"
            ),
            "loader.py": (
                "import pickle\n"
                "from downloader import download\n"
                "def load_remote_model(url):\n"
                "    data = download(url)\n"
                "    return pickle.loads(data)\n"
            ),
        })
        loader_path = str((root / "loader.py").resolve())

        seed_findings = [
            Finding(
                rule_id="NS-DESER-001",
                message="pickle.loads()",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path=loader_path,
                start_line=5,
                engine="neuroscan",
            ),
        ]

        result = _run_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        # The cross-file pass should at minimum detect that loader calls downloader
        # and downloader uses requests.get (a known propagator)
        assert len(cf) >= 1, "cross-file pass should emit a finding for the download -> pickle.loads chain"


class TestNoFalsePositiveCrossFile:
    """Same-file calls should NOT produce cross-file findings."""

    def test_same_file_no_crossfile(self):
        root = _make_project({
            "app.py": (
                "import pickle\n"
                "def get_data():\n"
                "    return b'test'\n"
                "def process():\n"
                "    data = get_data()\n"
                "    return pickle.loads(data)\n"
            ),
            "utils.py": (
                "def helper():\n"
                "    return 42\n"
            ),
        })
        app_path = str((root / "app.py").resolve())

        seed_findings = [
            Finding(
                rule_id="NS-DESER-001",
                message="pickle.loads()",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path=app_path,
                start_line=6,
                engine="neuroscan",
            ),
        ]

        result = _run_cross_file(root, seed_findings)
        cf = [f for f in result.findings if f.engine == "crossfile"]
        same_file = [f for f in cf if "app.py" in f.message and "app.py" in f.metadata.get("callee_file", "")]
        assert len(same_file) == 0, "Should NOT emit cross-file finding for same-file calls"


class TestPackageImports:
    """Test that package-style imports (from pkg.mod import func) resolve."""

    def test_package_import_resolution(self):
        root = _make_project({
            "main.py": (
                "from pkg.danger import execute\n"
                "def api_handler(request):\n"
                "    cmd = request.args.get('cmd')\n"
                "    execute(cmd)\n"
            ),
            "pkg/__init__.py": "",
            "pkg/danger.py": (
                "import os\n"
                "def execute(cmd):\n"
                "    os.system(cmd)\n"
            ),
        })
        danger_path = str((root / "pkg" / "danger.py").resolve())

        seed_findings = [
            Finding(
                rule_id="NS-INJECT-002",
                message="os.system()",
                severity=Severity.HIGH,
                category=Category.COMMAND_INJECTION,
                file_path=danger_path,
                start_line=3,
                engine="neuroscan",
            ),
        ]

        result = _run_cross_file(root, seed_findings)
        # Should at minimum not crash on package imports
        assert isinstance(result, ScanResult)


class TestSyntaxErrorResilience:
    """Malformed Python should not crash the pass."""

    def test_syntax_error_skipped(self):
        root = _make_project({
            "good.py": "def foo():\n    return 1\n",
            "bad.py": "def broken(\n    # missing closing paren\n",
            "also_good.py": "def bar():\n    return 2\n",
        })
        result = _run_cross_file(root)
        assert isinstance(result, ScanResult)


class TestEmptyProject:
    """Edge case: no Python files."""

    def test_no_python_files(self):
        root = _make_project({
            "readme.txt": "Not a Python project",
        })
        result = _run_cross_file(root)
        assert len(result.findings) == 0

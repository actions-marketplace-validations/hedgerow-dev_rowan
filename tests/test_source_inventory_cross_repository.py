"""Shared inventory contracts for repository-wide Python analyzers."""

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, SourceFile, SourceInventory
from rowan.passes.cross_file import CrossFilePass
from rowan.passes.file_scan import FileScanPass
from rowan.passes.js_cross_file import TREE_SITTER_AVAILABLE, JSCrossFilePass
from rowan.passes.multiagent import MultiAgentPass
from rowan.passes.serialization_scope import SerializationScopePass
from rowan.passes.sibling_gate import SiblingGatePass


def _context(root: Path) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(),
    )


def _finding_signature(result: ScanResult) -> list[tuple[str, str, int]]:
    return sorted(
        (finding.rule_id, finding.file_path, finding.start_line)
        for finding in result.findings
    )


@pytest.mark.parametrize(
    "pass_type", [CrossFilePass, SiblingGatePass, SerializationScopePass]
)
def test_reuses_inventory_without_repository_walk(tmp_path, monkeypatch, pass_type):
    (tmp_path / "one.py").write_text("def one():\n    return 1\n", encoding="utf-8")
    (tmp_path / "two.py").write_text("def two():\n    return 2\n", encoding="utf-8")
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    pass_type().run(context)


@pytest.mark.parametrize(
    "pass_type", [CrossFilePass, SiblingGatePass, SerializationScopePass]
)
def test_empty_inventory_is_authoritative(tmp_path, monkeypatch, pass_type):
    (tmp_path / "outside_scope.py").write_text(
        "def unsafe(value):\n    return eval(value)\n", encoding="utf-8"
    )
    context = _context(tmp_path)
    context.source_inventory = SourceInventory()

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.findings == []
    if pass_type is SerializationScopePass:
        assert result.files_scanned == 0


@pytest.mark.parametrize(
    "pass_type", [CrossFilePass, SiblingGatePass, SerializationScopePass]
)
def test_non_python_inventory_does_not_widen_scope(tmp_path, monkeypatch, pass_type):
    python_file = tmp_path / "outside_scope.py"
    python_file.write_text("value = eval(user_input)\n", encoding="utf-8")
    javascript_file = tmp_path / "inside_scope.js"
    javascript_file.write_text("const value = 1;\n", encoding="utf-8")
    context = _context(tmp_path)
    context.source_inventory = SourceInventory(files=(
        SourceFile(path=javascript_file, languages=frozenset({"javascript"})),
    ))

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.findings == []


def test_serialization_scope_inventory_matches_standalone_result(tmp_path):
    (tmp_path / "surfer.py").write_text(
        "class FileSurfer:\n"
        "    def __init__(self, name, base_path=None):\n"
        "        self.name = name\n"
        "        self._base_path = base_path\n"
        "\n"
        "    def _to_config(self):\n"
        "        return {'name': self.name}\n",
        encoding="utf-8",
    )

    standalone = SerializationScopePass().run(_context(tmp_path))
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)
    reused = SerializationScopePass().run(context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert reused.files_scanned == standalone.files_scanned == 1


def test_sibling_gate_inventory_matches_standalone_result(tmp_path):
    (tmp_path / "common.py").write_text(
        "import requests\n"
        "def safe_get(url):\n"
        "    if not url.startswith('https://trusted.example/'):\n"
        "        raise ValueError('untrusted URL')\n"
        "    return requests.get(url)\n",
        encoding="utf-8",
    )
    for index in range(3):
        (tmp_path / f"caller_{index}.py").write_text(
            "from common import safe_get\n"
            f"def caller_{index}(url):\n"
            "    return safe_get(url)\n",
            encoding="utf-8",
        )
    (tmp_path / "bypass.py").write_text(
        "import requests\n"
        "def bypass(url):\n"
        "    return requests.get(url)\n",
        encoding="utf-8",
    )

    standalone = SiblingGatePass().run(_context(tmp_path))
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)
    reused = SiblingGatePass().run(context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert len(reused.findings) == 1


def test_cross_file_inventory_preserves_existing_propagation(tmp_path, monkeypatch):
    source = tmp_path / "handler.py"
    sink = tmp_path / "sink.py"
    source.write_text(
        "from flask import request\n"
        "from sink import execute\n"
        "def handler():\n"
        "    execute(request.args.get('cmd'))\n",
        encoding="utf-8",
    )
    sink.write_text(
        "import os\n"
        "def execute(command):\n"
        "    return os.system(command)\n",
        encoding="utf-8",
    )
    finding = Finding(
        rule_id="NS-CMDI-001",
        message="command execution",
        severity=Severity.HIGH,
        category=Category.COMMAND_INJECTION,
        file_path=str(sink.resolve()),
        start_line=3,
        engine="opengrep",
    )

    standalone_context = _context(tmp_path)
    standalone_context.result = ScanResult(findings=[finding])
    standalone = CrossFilePass().run(standalone_context)

    context = _context(tmp_path)
    context.result = ScanResult(findings=[finding])
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    reused = CrossFilePass().run(context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert reused.findings


def _multiagent_context(root: Path) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root, enable_multiagent=True),
        result=ScanResult(),
    )


def test_multiagent_inventory_matches_standalone_without_walk(tmp_path, monkeypatch):
    (tmp_path / "crew.py").write_text(
        "from crewai import Agent, Task, Crew\n"
        "from crewai_tools import ScrapeWebsiteTool, CodeInterpreterTool\n"
        "researcher = Agent(role='Researcher', tools=[ScrapeWebsiteTool()])\n"
        "executor = Agent(role='Executor', tools=[CodeInterpreterTool()])\n"
        "research = Task(description='research', agent=researcher)\n"
        "execute = Task(description='execute', agent=executor, context=[research])\n"
        "crew = Crew(agents=[researcher, executor], tasks=[research, execute])\n",
        encoding="utf-8",
    )
    standalone = MultiAgentPass().run(_multiagent_context(tmp_path))

    context = _multiagent_context(tmp_path)
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    reused = MultiAgentPass().run(context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert reused.files_scanned == standalone.files_scanned == 1
    assert len(reused.findings) == 1


@pytest.mark.parametrize("inventory", [SourceInventory(), None])
def test_multiagent_empty_or_non_python_inventory_is_authoritative(
    tmp_path, monkeypatch, inventory
):
    (tmp_path / "outside_scope.py").write_text(
        "value = eval(user_input)\n", encoding="utf-8"
    )
    if inventory is None:
        javascript_file = tmp_path / "inside_scope.js"
        javascript_file.write_text("const value = 1;\n", encoding="utf-8")
        inventory = SourceInventory(files=(
            SourceFile(path=javascript_file, languages=frozenset({"javascript"})),
        ))
    context = _multiagent_context(tmp_path)
    context.source_inventory = inventory

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    result = MultiAgentPass().run(context)

    assert result.files_scanned == 0
    assert result.findings == []


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter unavailable")
def test_js_cross_file_inventory_matches_standalone_without_walk(tmp_path, monkeypatch):
    database = tmp_path / "db.ts"
    api = tmp_path / "api.js"
    database.write_text(
        "import fs from 'fs';\n"
        "export function readUserFile(filename: string) {\n"
        "  return fs.readFileSync(filename);\n"
        "}\n",
        encoding="utf-8",
    )
    api.write_text(
        "import { readUserFile } from './db';\n"
        "export function handler(req) {\n"
        "  return readUserFile(req.query.name);\n"
        "}\n",
        encoding="utf-8",
    )
    finding = Finding(
        rule_id="JS-PATH-001",
        message="filesystem path",
        severity=Severity.HIGH,
        category=Category.PATH_TRAVERSAL,
        file_path=str(database.resolve()),
        start_line=3,
        engine="opengrep",
    )
    standalone_context = _context(tmp_path)
    standalone_context.result = ScanResult(findings=[finding])
    standalone = JSCrossFilePass().run(standalone_context)

    context = _context(tmp_path)
    context.result = ScanResult(findings=[finding])
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    reused = JSCrossFilePass().run(context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert reused.findings


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter unavailable")
@pytest.mark.parametrize("inventory", [SourceInventory(), None])
def test_js_cross_file_empty_or_python_inventory_is_authoritative(
    tmp_path, monkeypatch, inventory
):
    (tmp_path / "outside_scope.js").write_text(
        "export const unsafe = input => eval(input);\n", encoding="utf-8"
    )
    if inventory is None:
        python_file = tmp_path / "inside_scope.py"
        python_file.write_text("value = 1\n", encoding="utf-8")
        inventory = SourceInventory(files=(
            SourceFile(path=python_file, languages=frozenset({"python"})),
        ))
    context = _context(tmp_path)
    context.source_inventory = inventory

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    result = JSCrossFilePass().run(context)

    assert result.findings == []

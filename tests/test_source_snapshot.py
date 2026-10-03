"""Scan-lifetime source text and Python AST snapshot behavior."""

import ast
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.agent_flow import AgentFlowPass
from rowan.passes.authz import AuthzPass
from rowan.passes.base import (
    ScanContext,
    SourceFile,
    SourceInventory,
    SourceSnapshot,
)
from rowan.passes.config_taint import ConfigTaintPass
from rowan.passes.dormant_code import DormantCodePass
from rowan.passes.membership_inference import MembershipInferencePass
from rowan.passes.model_extraction import ModelExtractionPass
from rowan.passes.pii_egress import PiiEgressPass
from rowan.passes.training_approval import TrainingApprovalPass
from rowan.passes.training_disclosure import TrainingDisclosurePass
from rowan.passes.web_security import WebSecurityPass

_PYTHON_AST_CONSUMERS = (
    PiiEgressPass,
    TrainingDisclosurePass,
    ModelExtractionPass,
    ConfigTaintPass,
    TrainingApprovalPass,
    DormantCodePass,
    MembershipInferencePass,
)


def _context(root: Path, source: Path) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(),
        source_inventory=SourceInventory(
            (SourceFile(source, frozenset({"python"})),)
        ),
    )


def _assigned_integer(tree: ast.Module) -> int:
    assignment = tree.body[0]
    assert isinstance(assignment, ast.Assign)
    assert isinstance(assignment.value, ast.Constant)
    assert isinstance(assignment.value.value, int)
    return assignment.value.value


def test_migrated_passes_share_one_text_read_and_python_parse(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def clean():\n    return 1\n", encoding="utf-8")
    context = _context(tmp_path, source)
    reads = 0
    parses = 0
    original_read_text = Path.read_text
    original_parse = ast.parse

    def counted_read_text(self, *args, **kwargs):
        nonlocal reads
        if self == source:
            reads += 1
        return original_read_text(self, *args, **kwargs)

    def counted_parse(*args, **kwargs):
        nonlocal parses
        parses += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read_text)
    monkeypatch.setattr(ast, "parse", counted_parse)

    for pass_type in _PYTHON_AST_CONSUMERS:
        pass_type().run(context)

    assert reads == 1
    assert parses == 1


def test_web_facing_passes_share_one_text_read_and_python_parse(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text("def clean():\n    return 1\n", encoding="utf-8")
    context = _context(tmp_path, source)
    context.config.enable_authz = True
    reads = 0
    parses = 0
    original_read_text = Path.read_text
    original_parse = ast.parse

    def counted_read_text(self, *args, **kwargs):
        nonlocal reads
        if self == source:
            reads += 1
        return original_read_text(self, *args, **kwargs)

    def counted_parse(*args, **kwargs):
        nonlocal parses
        parses += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read_text)
    monkeypatch.setattr(ast, "parse", counted_parse)

    AgentFlowPass().run(context)
    WebSecurityPass().run(context)
    AuthzPass().run(context)

    assert reads == 1
    assert parses == 1


def test_web_facing_passes_share_cached_parse_failure(tmp_path, monkeypatch):
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")
    context = _context(tmp_path, source)
    context.config.enable_authz = True
    parses = 0
    original_parse = ast.parse

    def counted_parse(*args, **kwargs):
        nonlocal parses
        parses += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)

    assert AgentFlowPass().run(context).files_scanned == 0
    assert WebSecurityPass().run(context).files_scanned == 0
    assert AuthzPass().run(context).files_scanned == 0
    assert parses == 1


def test_web_facing_passes_receive_isolated_ast_copies(tmp_path, monkeypatch):
    source = tmp_path / "app.py"
    source.write_text(
        "def current_user():\n"
        "    return request.user\n\n"
        "@app.get('/documents/<pk>')\n"
        "def document_detail(request, pk):\n"
        "    document = Document.objects.get(id=pk)\n"
        "    return render(document)\n",
        encoding="utf-8",
    )
    context = _context(tmp_path, source)
    context.config.enable_authz = True

    def mutate_agent_copy(functions):
        for function in functions:
            function.node.decorator_list.clear()
        return {}

    monkeypatch.setattr(
        AgentFlowPass,
        "_budget_sinks",
        staticmethod(mutate_agent_copy),
    )

    AgentFlowPass().run(context)
    result = AuthzPass().run(context)

    assert [finding.rule_id for finding in result.findings] == ["AUTHZ-BOLA-001"]


def test_python_parse_failure_is_cached_across_migrated_passes(tmp_path, monkeypatch):
    source = tmp_path / "broken.py"
    source.write_text("def broken(:\n", encoding="utf-8")
    context = _context(tmp_path, source)
    parses = 0
    original_parse = ast.parse

    def counted_parse(*args, **kwargs):
        nonlocal parses
        parses += 1
        return original_parse(*args, **kwargs)

    monkeypatch.setattr(ast, "parse", counted_parse)

    for pass_type in _PYTHON_AST_CONSUMERS:
        assert pass_type().run(context).files_scanned == 0
    assert parses == 1
    assert context.source_snapshot.stats()["parse_failures"] == 1


def test_text_read_failure_is_cached(tmp_path, monkeypatch):
    source = tmp_path / "unreadable.py"
    attempts = 0

    def failed_read_text(self, *args, **kwargs):
        nonlocal attempts
        attempts += 1
        raise OSError("unreadable")

    monkeypatch.setattr(Path, "read_text", failed_read_text)
    snapshot = SourceSnapshot()

    assert snapshot.read_text(source) is None
    assert snapshot.read_text(source) is None
    assert snapshot.python_ast(source) is None
    assert attempts == 1
    assert snapshot.stats()["read_failures"] == 1


def test_read_failure_is_shared_across_migrated_passes(tmp_path, monkeypatch):
    source = tmp_path / "unreadable.py"
    context = _context(tmp_path, source)
    attempts = 0

    def failed_read_text(self, *args, **kwargs):
        nonlocal attempts
        if self == source:
            attempts += 1
            raise OSError("unreadable")
        return ""

    monkeypatch.setattr(Path, "read_text", failed_read_text)

    for pass_type in _PYTHON_AST_CONSUMERS:
        result = pass_type().run(context)
        assert result.files_scanned == 0
        assert result.findings == []

    assert attempts == 1


def test_python_ast_returns_defensive_copies(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot = SourceSnapshot()

    first = snapshot.python_ast(source)
    assert first is not None
    first.body.clear()

    second = snapshot.python_ast(source)
    assert second is not None
    assert _assigned_integer(second) == 1


def test_file_edits_are_visible_to_new_context_not_existing_snapshot(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    first_context = _context(tmp_path, source)
    first_tree = first_context.source_snapshot.python_ast(source)
    assert first_tree is not None
    assert _assigned_integer(first_tree) == 1

    source.write_text("value = 2\n", encoding="utf-8")

    retained_tree = first_context.source_snapshot.python_ast(source)
    second_tree = _context(tmp_path, source).source_snapshot.python_ast(source)
    assert retained_tree is not None
    assert second_tree is not None
    assert _assigned_integer(retained_tree) == 1
    assert _assigned_integer(second_tree) == 2


def test_snapshot_entry_bound_evicts_least_recent_source(tmp_path, monkeypatch):
    first = tmp_path / "first.py"
    second = tmp_path / "second.py"
    first.write_text("first = 1\n", encoding="utf-8")
    second.write_text("second = 2\n", encoding="utf-8")
    reads = 0
    original_read_text = Path.read_text

    def counted_read_text(self, *args, **kwargs):
        nonlocal reads
        reads += 1
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read_text)
    snapshot = SourceSnapshot(max_entries=1)

    assert snapshot.read_text(first) is not None
    assert snapshot.read_text(second) is not None
    assert snapshot.read_text(first) is not None
    assert reads == 3


def test_snapshot_stats_are_path_free_and_count_cache_reuse(tmp_path):
    source = tmp_path / "app.py"
    source.write_text("value = 1\n", encoding="utf-8")
    snapshot = SourceSnapshot()

    assert snapshot.python_ast(source) is not None
    assert snapshot.python_ast(source) is not None

    assert snapshot.stats() == {
        "text_entries": 1,
        "python_ast_entries": 1,
        "text_hits": 0,
        "text_misses": 1,
        "python_ast_hits": 1,
        "python_ast_misses": 1,
        "read_failures": 0,
        "parse_failures": 0,
    }

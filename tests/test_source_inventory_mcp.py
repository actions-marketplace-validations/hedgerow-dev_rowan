"""Shared source-inventory reuse by Python MCP structural passes."""

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext, SourceInventory
from rowan.passes.file_scan import FileScanPass
from rowan.passes.mcp_network_exposure import MCPNetworkExposurePass
from rowan.passes.mcp_sampling_approval import MCPSamplingApprovalPass
from rowan.passes.mcp_stored_content import MCPStoredContentPass
from rowan.passes.mcp_tool_metadata import MCPToolMetadataPass

_MCP_INVENTORY_CONSUMERS = (
    MCPNetworkExposurePass,
    MCPSamplingApprovalPass,
    MCPStoredContentPass,
)


def _context(root: Path, *, languages: list[str] | None = None) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root, languages=languages or []),
        result=ScanResult(),
    )


def _write_fixture(root: Path, pass_type) -> None:
    if pass_type is MCPNetworkExposurePass:
        (root / "server.py").write_text(
            "from mcp.server import Server\n"
            "import uvicorn\n"
            "server = Server('inventory')\n"
            "app = server.streamable_http_app()\n"
            "uvicorn.run(app, host='0.0.0.0')\n",
            encoding="utf-8",
        )
    elif pass_type is MCPSamplingApprovalPass:
        (root / "client.py").write_text(
            "from mcp import Client\n"
            "async def decide(context, params):\n"
            "    return CreateMessageResult(content=sample(params))\n"
            "client = Client('https://example.test', sampling_callback=decide)\n",
            encoding="utf-8",
        )
    else:
        (root / "writer.py").write_text(
            "@require_auth\n"
            "def set_note():\n"
            "    data = request.get_json()\n"
            "    note = ToolNote(note=data.get('note'))\n",
            encoding="utf-8",
        )
        (root / "server.py").write_text(
            "async def summarize(session):\n"
            "    row = ToolNote.query.first()\n"
            "    content = row.note\n"
            "    return await session.create_message(messages=[content])\n",
            encoding="utf-8",
        )


def _signature(result: ScanResult) -> list[tuple[str, str, int]]:
    return sorted(
        (finding.rule_id, finding.file_path, finding.start_line)
        for finding in result.findings
    )


@pytest.mark.parametrize("pass_type", _MCP_INVENTORY_CONSUMERS)
def test_mcp_inventory_results_match_standalone(tmp_path, pass_type):
    _write_fixture(tmp_path, pass_type)

    standalone = pass_type().run(_context(tmp_path))
    shared_context = _context(tmp_path)
    FileScanPass(rules=[]).run(shared_context)
    reused = pass_type().run(shared_context)

    assert _signature(reused) == _signature(standalone)
    assert reused.files_scanned == standalone.files_scanned


@pytest.mark.parametrize("pass_type", _MCP_INVENTORY_CONSUMERS)
def test_mcp_pass_reuses_inventory_without_repository_walk(tmp_path, monkeypatch, pass_type):
    (tmp_path / "clean.py").write_text("def clean():\n    return 1\n", encoding="utf-8")
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 1


@pytest.mark.parametrize("pass_type", _MCP_INVENTORY_CONSUMERS)
def test_mcp_pass_treats_empty_inventory_as_authoritative(tmp_path, monkeypatch, pass_type):
    _write_fixture(tmp_path, pass_type)
    context = _context(tmp_path)
    context.source_inventory = SourceInventory()

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


@pytest.mark.parametrize("pass_type", _MCP_INVENTORY_CONSUMERS)
def test_mcp_pass_respects_non_python_language_scope(tmp_path, monkeypatch, pass_type):
    _write_fixture(tmp_path, pass_type)
    (tmp_path / "inside_scope.js").write_text("const value = 1;\n", encoding="utf-8")
    context = _context(tmp_path, languages=["javascript"])
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


@pytest.mark.parametrize("pass_type", _MCP_INVENTORY_CONSUMERS)
def test_mcp_inventory_and_standalone_preserve_hidden_and_ignore_exclusions(
    tmp_path, pass_type
):
    included = tmp_path / "included.py"
    included.write_text("def included():\n    return 1\n", encoding="utf-8")
    hidden = tmp_path / ".fixtures"
    hidden.mkdir()
    (hidden / "hidden.py").write_text("def hidden():\n    return 1\n", encoding="utf-8")
    ignored = tmp_path / "ignored.py"
    ignored.write_text("def ignored():\n    return 1\n", encoding="utf-8")
    (tmp_path / ".rowanignore").write_text("ignored.py\n", encoding="utf-8")

    standalone = pass_type().run(_context(tmp_path))
    shared_context = _context(tmp_path)
    FileScanPass(rules=[]).run(shared_context)
    reused = pass_type().run(shared_context)

    assert standalone.files_scanned == 1
    assert reused.files_scanned == 1
    assert standalone.findings == reused.findings == []


def test_mcp_tool_metadata_reuses_authoritative_python_inventory(
    tmp_path, monkeypatch
):
    (tmp_path / "server.py").write_text(
        "tool = Tool(name='read', description='safe')\n"
        "tool.description = request.args['description']\n",
        encoding="utf-8",
    )
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    result = MCPToolMetadataPass().run(context)

    assert [finding.rule_id for finding in result.findings] == ["MCP-TOCTOU-001"]
    assert result.files_scanned == 1


def test_mcp_tool_metadata_empty_inventory_never_widens_scope(
    tmp_path, monkeypatch
):
    (tmp_path / "server.py").write_text(
        "tool = Tool(name='read', description='safe')\n"
        "tool.description = 'changed'\n",
        encoding="utf-8",
    )
    context = _context(tmp_path)
    context.source_inventory = SourceInventory()

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)
    result = MCPToolMetadataPass().run(context)

    assert result.findings == []
    assert result.files_scanned == 0


def test_mcp_tool_metadata_reuses_snapshot_parse(tmp_path, monkeypatch):
    source = tmp_path / "server.py"
    source.write_text(
        "tool = Tool(name='read', description='safe')\n"
        "tool.description = 'changed'\n",
        encoding="utf-8",
    )
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)
    original_read_text = Path.read_text
    reads = 0

    def counted_read_text(self, *args, **kwargs):
        nonlocal reads
        if self == source:
            reads += 1
        return original_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", counted_read_text)

    first = MCPToolMetadataPass().run(context)
    second = MCPToolMetadataPass().run(context)

    assert _signature(first) == _signature(second)
    assert reads == 1
    assert context.source_snapshot.stats()["python_ast_misses"] == 1
    assert context.source_snapshot.stats()["python_ast_hits"] == 1

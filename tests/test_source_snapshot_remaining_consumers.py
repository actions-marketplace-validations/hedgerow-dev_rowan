"""Shared snapshot reuse by the remaining Python structural consumers."""

import ast
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext, SourceFile, SourceInventory
from rowan.passes.mcp_network_exposure import MCPNetworkExposurePass
from rowan.passes.mcp_sampling_approval import MCPSamplingApprovalPass
from rowan.passes.mcp_stored_content import MCPStoredContentPass
from rowan.passes.multiagent import MultiAgentPass
from rowan.passes.serialization_scope import SerializationScopePass

_CONSUMERS = (
    MCPNetworkExposurePass,
    MCPSamplingApprovalPass,
    MCPStoredContentPass,
    MultiAgentPass,
    SerializationScopePass,
)


def _context(root: Path, source: Path) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root, enable_multiagent=True),
        result=ScanResult(),
        source_inventory=SourceInventory(
            (SourceFile(source, frozenset({"python"})),)
        ),
    )


def test_structural_consumers_share_one_text_read_and_parse(tmp_path, monkeypatch):
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

    results = [pass_type().run(context) for pass_type in _CONSUMERS]

    assert [result.files_scanned for result in results] == [1] * len(_CONSUMERS)
    assert reads == 1
    assert parses == 1


def test_structural_consumers_share_cached_parse_failure(tmp_path, monkeypatch):
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

    results = [pass_type().run(context) for pass_type in _CONSUMERS]

    assert [result.files_scanned for result in results] == [0] * len(_CONSUMERS)
    assert parses == 1


def test_ast_mutation_in_one_consumer_does_not_leak_to_the_next(tmp_path, monkeypatch):
    source = tmp_path / "client.py"
    source.write_text(
        "from mcp import Client\n"
        "async def decide(context, params):\n"
        "    return CreateMessageResult(content=sample(params))\n"
        "client = Client('https://example.test', sampling_callback=decide)\n",
        encoding="utf-8",
    )
    context = _context(tmp_path, source)

    def destructive_scan(self, path, tree, all_interfaces, disabled_auth):
        tree.body.clear()
        return []

    monkeypatch.setattr(MCPNetworkExposurePass, "_scan_file", destructive_scan)

    MCPNetworkExposurePass().run(context)
    result = MCPSamplingApprovalPass().run(context)

    assert [finding.rule_id for finding in result.findings] == [
        "MCP-SAMPLING-APPROVAL-001"
    ]

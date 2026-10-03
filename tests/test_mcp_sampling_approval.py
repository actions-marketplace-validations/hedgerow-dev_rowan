from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.mcp_sampling_approval import MCPSamplingApprovalPass
from rowan.pipeline import ScanPipeline


def _scan(tmp_path: Path, source: str):
    (tmp_path / "client.py").write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return MCPSamplingApprovalPass().run(context).findings


def test_registered_purpose_named_callback_without_review_is_flagged(tmp_path):
    source = """\
from mcp import Client

async def decide_server_request(context, params):
    return CreateMessageResult(content=sample_with_local_model(params))

client = Client("http://server.example/mcp", sampling_callback=decide_server_request)
"""
    findings = _scan(tmp_path, source)
    assert [finding.rule_id for finding in findings] == ["MCP-SAMPLING-APPROVAL-001"]
    assert findings[0].start_line == 3


def test_client_session_alias_is_supported(tmp_path):
    source = """\
from mcp.client.session import ClientSession as Session

async def choose_response(context, params):
    return CreateMessageResult(content=sample_with_local_model(params))

session = Session(dispatcher, sampling_callback=choose_response)
"""
    assert [finding.rule_id for finding in _scan(tmp_path, source)] == ["MCP-SAMPLING-APPROVAL-001"]


def test_visible_human_review_suppresses_the_finding(tmp_path):
    source = """\
from mcp import Client

async def decide_server_request(context, params):
    if not await confirm_with_user(params):
        return ErrorData(message="declined")
    return CreateMessageResult(content=sample_with_local_model(params))

client = Client("http://server.example/mcp", sampling_callback=decide_server_request)
"""
    assert _scan(tmp_path, source) == []


def test_non_mcp_client_and_disabled_callback_are_not_flagged(tmp_path):
    source = """\
from another_package import Client

async def decide_server_request(context, params):
    return CreateMessageResult(content=sample_with_local_model(params))

client = Client(sampling_callback=decide_server_request)
mcp_client = None
"""
    assert _scan(tmp_path, source) == []


def test_pipeline_includes_registered_sampling_callback_check(tmp_path):
    (tmp_path / "client.py").write_text(
        "from mcp import Client\n"
        "async def decide(context, params):\n"
        "    return CreateMessageResult(content='ok')\n"
        "client = Client('http://server.example/mcp', sampling_callback=decide)\n",
        encoding="utf-8",
    )
    result = ScanPipeline(
        ScanConfig(target=tmp_path, no_taint=True, no_sca=True, no_cross_file=True)
    ).run()
    assert any(finding.rule_id == "MCP-SAMPLING-APPROVAL-001" for finding in result.findings)

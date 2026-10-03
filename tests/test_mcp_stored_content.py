from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.mcp_stored_content import MCPStoredContentPass


def _scan(root: Path, writer: str, server: str):
    (root / "writer.py").write_text(writer, encoding="utf-8")
    (root / "server.py").write_text(server, encoding="utf-8")
    return MCPStoredContentPass().run(
        ScanContext(root, ScanConfig(root), ScanResult())
    ).findings


_AUTH_WRITER = """
@require_auth
def set_tool_note():
    data = request.get_json() or {}
    note = ToolNote(tool_name=data.get('tool'), note=data.get('note'))
    db.session.add(note)
"""

_ADMIN_WRITER = _AUTH_WRITER.replace("@require_auth", "@require_admin")


def test_low_privilege_stored_note_reaching_mcp_metadata_is_reported(tmp_path: Path) -> None:
    server = """
def tool_description(name):
    row = ToolNote.query.filter_by(tool_name=name).first()
    content = row.note if row else ''
    return 'Tool docs: ' + content

def list_tools():
    return types.Tool(name='search', description=tool_description('search'), inputSchema={})
"""
    findings = _scan(tmp_path, _AUTH_WRITER, server)
    assert [finding.rule_id for finding in findings] == [
        "MCP-STORED-METADATA-AUTHZ-001"
    ]
    assert findings[0].cwe_ids == [862]


def test_low_privilege_stored_note_reaching_sampling_is_reported(tmp_path: Path) -> None:
    server = """
async def summarize(session, tool_name):
    row = ToolNote.query.filter_by(tool_name=tool_name).first()
    content = row.note if row else ''
    return await session.create_message(messages=[SamplingMessage(text=content)])
"""
    findings = _scan(tmp_path, _AUTH_WRITER, server)
    assert [finding.rule_id for finding in findings] == ["MCP-STORED-SAMPLING-001"]
    assert findings[0].cwe_ids == [20]


def test_administrator_only_writer_does_not_arm_channel(tmp_path: Path) -> None:
    server = """
async def summarize(session, tool_name):
    row = ToolNote.query.filter_by(tool_name=tool_name).first()
    content = row.note if row else ''
    return await session.create_message(messages=[SamplingMessage(text=content)])
"""
    assert _scan(tmp_path, _ADMIN_WRITER, server) == []


def test_sanitized_stored_content_does_not_reach_sampling(tmp_path: Path) -> None:
    server = """
async def summarize(session, tool_name):
    row = ToolNote.query.filter_by(tool_name=tool_name).first()
    content = strip_directives(row.note if row else '')
    return await session.create_message(messages=[SamplingMessage(text=content)])
"""
    assert _scan(tmp_path, _AUTH_WRITER, server) == []


def test_different_model_field_does_not_cross_contaminate(tmp_path: Path) -> None:
    server = """
async def summarize(session, tool_name):
    row = DeploymentMessage.query.filter_by(tool_name=tool_name).first()
    content = row.note if row else ''
    return await session.create_message(messages=[SamplingMessage(text=content)])
"""
    assert _scan(tmp_path, _AUTH_WRITER, server) == []

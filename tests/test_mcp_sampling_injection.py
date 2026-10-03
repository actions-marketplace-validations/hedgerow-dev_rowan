"""LangFail V39: untrusted MCP tool-handler input flowing into an MCP
sampling request (create_message / ctx.sample) across low-level and
high-level SDK shapes (rules/agent_taint.yaml, TNT-ML-036).

An MCP server can ask the client's own LLM to generate a completion via a
sampling request. When the messages in that request are built from
caller-supplied tool-handler input, a malicious MCP client injects a prompt
directly into the host model's context. Sources reuse TNT-ML-025's proven
tool-handler-parameter shape; sinks are the sampling calls.

Requires the Opengrep binary (skipped entirely if not installed, matching
this project's convention).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "agent_taint.yaml"
RULE_ID = "TNT-ML-036"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, source):
    fp = tmp_path / "server.py"
    fp.write_text(source, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == RULE_ID]


class TestVulnerable:
    def test_handler_param_into_session_create_message(self, tmp_path):
        src = '''
from mcp.types import SamplingMessage, TextContent

@mcp.tool()
async def summarize(ctx, note):
    result = await ctx.session.create_message(
        messages=[SamplingMessage(role="user", content=TextContent(type="text", text=note))],
        max_tokens=100,
    )
    return result
'''
        assert len(_scan(tmp_path, src)) == 1

    def test_handler_param_into_ctx_sample(self, tmp_path):
        src = '''
@server.tool()
async def ask(ctx, question):
    return await ctx.sample(question)
'''
        assert len(_scan(tmp_path, src)) == 1


class TestSafe:
    def test_fixed_literal_prompt_not_flagged(self, tmp_path):
        # The caller-supplied param is unused; the sampling prompt is a fixed
        # literal, so nothing untrusted reaches the sink.
        src = '''
from mcp.types import SamplingMessage, TextContent

@mcp.tool()
async def ping(ctx, note):
    return await ctx.session.create_message(
        messages=[SamplingMessage(role="user", content=TextContent(type="text", text="fixed prompt"))],
        max_tokens=10,
    )
'''
        assert _scan(tmp_path, src) == []

    def test_dataframe_sample_not_flagged(self, tmp_path):
        # `.sample(` on a non-context receiver is a pandas/random call, not an
        # MCP sampling request -- the receiver constraint must exclude it.
        src = '''
@mcp.tool()
async def rows(df, n):
    return df.sample(n)
'''
        assert _scan(tmp_path, src) == []

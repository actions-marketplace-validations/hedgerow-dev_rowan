"""Tests for ns-aiml-125..128 (rules/ai_security.yaml): MCP attack classes
beyond the basics (issue #141) -- tool description poisoning, unauthenticated
network transports, and un-gated sampling approval.
"""

from __future__ import annotations

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id: str):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestNsAiml125ToolDescriptionPoisoning:
    def test_non_literal_description_flagged(self, tmp_path):
        fp = tmp_path / "poison.py"
        fp.write_text(
            "desc = fetch_description()\n"
            "@mcp.tool(description=desc)\n"
            "def transfer(amount, to): ...\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-125").check(fp)

    def test_literal_description_not_flagged(self, tmp_path):
        fp = tmp_path / "clean.py"
        fp.write_text(
            '@mcp.tool(description="Transfer funds between accounts")\n'
            "def transfer(amount, to): ...\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-125").check(fp) == []

    def test_unrelated_object_description_kwarg_not_flagged(self, tmp_path):
        """Regression guard: found scanning scan-targets/letta --
        `AgentState(..., description=agent_state.description, ...)` is an
        agent's own bio/description field, not an MCP tool description, but
        previously matched since the rule had no requirement that the call
        actually be a tool constructor. `description=` is far too common a
        kwarg name across unrelated object types to use as a standalone
        signal."""
        fp = tmp_path / "agent_state.py"
        fp.write_text(
            "def build(agent_state):\n"
            "    return AgentState(\n"
            "        embedding_config=agent_state.embedding_config,\n"
            "        description=agent_state.description,\n"
            "        metadata=agent_state.metadata,\n"
            "    )\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-125").check(fp) == []

    def test_unrelated_kwarg_substring_inside_tool_call_not_flagged(self, tmp_path):
        """Regression guard: `inner_thoughts_description=...` previously
        matched because the old pattern lacked a word boundary on
        "description", so it matched as a substring of any longer
        identifier ending in that word -- even inside an actual Tool(...)
        call, where it's still not the tool's own description field."""
        fp = tmp_path / "tool_call.py"
        fp.write_text(
            "def build(inner_thoughts_desc):\n"
            "    return Tool(name='x', inner_thoughts_description=inner_thoughts_desc)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-125").check(fp) == []


class TestNsAiml126AllInterfacesBind:
    def test_host_0000_flagged(self, tmp_path):
        fp = tmp_path / "expose.py"
        fp.write_text('mcp.run(host="0.0.0.0")\n', encoding="utf-8")
        assert _rule("ns-aiml-126").check(fp)

    def test_localhost_not_flagged(self, tmp_path):
        fp = tmp_path / "local.py"
        fp.write_text('mcp.run(host="127.0.0.1")\n', encoding="utf-8")
        assert _rule("ns-aiml-126").check(fp) == []


class TestNsAiml127UnauthTransport:
    def test_sse_transport_no_auth_flagged(self, tmp_path):
        fp = tmp_path / "sse.py"
        fp.write_text('mcp.run(transport="sse")\n', encoding="utf-8")
        assert _rule("ns-aiml-127").check(fp)

    def test_sse_transport_with_auth_not_flagged(self, tmp_path):
        fp = tmp_path / "sse_auth.py"
        fp.write_text(
            "mcp.run(transport='sse', auth_provider=BearerAuthProvider())\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-127").check(fp) == []

    def test_stdio_transport_not_flagged(self, tmp_path):
        fp = tmp_path / "stdio.py"
        fp.write_text("mcp.run(transport='stdio')\n", encoding="utf-8")
        assert _rule("ns-aiml-127").check(fp) == []


class TestNsAiml128SamplingAutoApproval:
    def test_sampling_callback_no_confirm_flagged(self, tmp_path):
        fp = tmp_path / "auto_approve.py"
        fp.write_text(
            "def sampling_createmessage_handler(request):\n"
            "    return SamplingResult(approved=True)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-128").check(fp)

    def test_sampling_callback_with_confirm_not_flagged(self, tmp_path):
        fp = tmp_path / "gated.py"
        fp.write_text(
            "def sampling_createmessage_handler(request):\n"
            "    if not confirm_with_user(request):\n"
            "        return SamplingResult(approved=False)\n"
            "    return SamplingResult(approved=True)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-128").check(fp) == []

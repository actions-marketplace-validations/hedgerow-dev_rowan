"""Fixtures for TNT-ML-024/025 (rules/agent_taint.yaml), issue #141:
config/env/network source into MCP tool registration (rug pull), and
MCP tool-handler-parameter confused-deputy token passthrough.

Requires the Opengrep binary (skipped entirely if not installed, matching
this project's convention).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "agent_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestTntMl024ToolRegistrationPoisoning:
    """Config/env/network source flowing into an MCP tool's registered
    name/description."""

    def test_network_fetched_description_flagged(self, tmp_path):
        src = (
            "import httpx\n"
            "server = object()\n"
            "remote_desc = httpx.get('https://registry.example.com/desc').json()['description']\n"
            "server.add_tool(name='search', description=remote_desc)\n"
        )
        findings = _scan(tmp_path, "tool_poison.py", src, "TNT-ML-024")
        assert findings, "a network-fetched tool description must be flagged"

    def test_env_sourced_description_flagged(self, tmp_path):
        src = (
            "import os\n"
            "server = object()\n\n"
            "def register():\n"
            "    desc = os.getenv('TOOL_DESC')\n"
            "    server.add_tool(name='transfer', description=desc)\n"
        )
        findings = _scan(tmp_path, "tool_poison_env.py", src, "TNT-ML-024")
        assert findings, "an env-sourced tool description must be flagged"

    def test_literal_description_not_flagged(self, tmp_path):
        src = (
            "server = object()\n"
            "server.add_tool(name='search', description='Search the knowledge base')\n"
        )
        findings = _scan(tmp_path, "tool_clean.py", src, "TNT-ML-024")
        assert findings == [], "a literal string description must not be flagged"


class TestTntMl025ConfusedDeputy:
    """MCP tool-handler parameter flowing into an upstream authenticated
    call whose credential is a fixed module-level/env constant."""

    def test_mcp_tool_decorator_flagged(self, tmp_path):
        src = (
            "import os\n"
            "import httpx\n"
            "UPSTREAM_TOKEN = os.environ['UPSTREAM_API_KEY']\n\n"
            "@mcp.tool()\n"
            "async def fetch_account(account_id):\n"
            "    client = httpx.Client()\n"
            "    resp = client.get(f'https://upstream.example.com/accounts/{account_id}', "
            "headers={'Authorization': UPSTREAM_TOKEN})\n"
            "    return resp.json()\n"
        )
        findings = _scan(tmp_path, "confused_deputy.py", src, "TNT-ML-025")
        assert findings, "MCP tool parameter reaching an upstream authed call must be flagged"

    def test_server_tool_decorator_variant_flagged(self, tmp_path):
        src = (
            "import os\n"
            "import httpx\n"
            "UPSTREAM_TOKEN = os.environ['UPSTREAM_API_KEY']\n\n"
            "@server.tool()\n"
            "async def fetch_account(account_id):\n"
            "    client = httpx.Client()\n"
            "    resp = client.get(f'https://upstream.example.com/accounts/{account_id}', "
            "headers={'Authorization': UPSTREAM_TOKEN})\n"
            "    return resp.json()\n"
        )
        findings = _scan(tmp_path, "confused_deputy_server.py", src, "TNT-ML-025")
        assert findings, "@server.tool() naming variant must also be flagged"

    def test_no_mcp_tool_decorator_not_flagged(self, tmp_path):
        """A plain function (not an MCP tool handler) using the same
        credential shape is not this rule's concern -- no caller-supplied
        MCP parameter is in play."""
        src = (
            "import os\n"
            "import httpx\n"
            "UPSTREAM_TOKEN = os.environ['UPSTREAM_API_KEY']\n\n"
            "def internal_job(account_id):\n"
            "    client = httpx.Client()\n"
            "    resp = client.get(f'https://upstream.example.com/accounts/{account_id}', "
            "headers={'Authorization': UPSTREAM_TOKEN})\n"
            "    return resp.json()\n"
        )
        findings = _scan(tmp_path, "not_an_mcp_tool.py", src, "TNT-ML-025")
        assert findings == [], "a non-MCP-tool function must not be flagged"

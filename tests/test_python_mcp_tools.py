"""Python MCP servers: FastMCP tools and low-level call_tool handlers."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "benchmark" / "ground_truth" / "py_agent_cases"

_SERVER = '''import subprocess

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("demo")


@mcp.tool()
def read_file(path: str) -> str:
    with open(path) as f:
        return f.read()


@mcp.tool()
def run(cmd: str) -> str:
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout


@mcp.tool()
def fetch(url: str) -> str:
    return requests.get(url).text
'''


def test_single_file_fastmcp_server_reports_high_for_each_sink(tmp_path):
    # One-file servers are common; the model chooses every tool argument, so
    # file-level context (a library profile, no web import, a local `open(`)
    # must not demote these.
    (tmp_path / "server.py").write_text(_SERVER, encoding="utf-8")

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    tool_findings = {
        f.start_line: f.severity for f in result.findings if f.rule_id == "AGENT-TOOL-001"
    }
    assert tool_findings == {11: Severity.HIGH, 17: Severity.HIGH, 22: Severity.HIGH}


@pytest.mark.skipif(not OpengrepAdapter().is_installed(), reason="Opengrep binary is required")
def test_python_mcp_pairs_detect_only_vulnerable_files():
    spec = importlib.util.spec_from_file_location("benchmark_py_agent", ROOT / "scripts" / "benchmark.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_py_agent"] = module
    spec.loader.exec_module(module)
    report = module.run_py_agent_cases(CORPUS)
    assert not report["degraded"]
    assert report["hits"] == report["total"] == 11
    assert report["false_positives"] == 0


def test_validator_statement_and_guard_hook_stop_the_tool_argument(tmp_path):
    (tmp_path / "net.py").write_text(
        "import httpx\n"
        "\n"
        "\n"
        "async def fetch_raw(url: str) -> bytes:\n"
        "    async with httpx.AsyncClient() as client:\n"
        "        return (await client.get(url)).content\n"
        "\n"
        "\n"
        "async def fetch_hooked(url: str) -> bytes:\n"
        '    async with httpx.AsyncClient(event_hooks={"request": [ssrf_guard]}) as client:\n'
        "        return (await client.get(url)).content\n",
        encoding="utf-8",
    )
    (tmp_path / "server.py").write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "\n"
        "from net import fetch_hooked, fetch_raw\n"
        "\n"
        'mcp = FastMCP("img")\n'
        "\n"
        "\n"
        "@mcp.tool()\n"
        "async def raw(url: str) -> int:\n"
        "    return len(await fetch_raw(url))\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "async def checked(url: str) -> int:\n"
        "    validate_public_url(url)\n"
        "    return len(await fetch_raw(url))\n"
        "\n"
        "\n"
        "@mcp.tool()\n"
        "async def hooked(url: str) -> int:\n"
        "    return len(await fetch_hooked(url))\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    callers = sorted(
        f.metadata["caller"] for f in result.findings if f.rule_id == "AGENT-TOOL-001"
    )
    assert callers == ["raw"]

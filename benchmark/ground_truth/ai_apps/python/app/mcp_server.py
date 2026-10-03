"""FastMCP 2 server exposing host tools, plus the client that talks to peers."""

from __future__ import annotations

import os
import subprocess

import httpx
from fastmcp import Client, FastMCP
from fastmcp.client.sampling import SamplingMessage, SamplingParams
from fastmcp.server.auth.providers.jwt import JWTVerifier
from openai import OpenAI

mcp = FastMCP("oracle-host")
openai_client = OpenAI()


@mcp.tool
def host_exec(cmd: str) -> str:
    """Run a diagnostic command on the host and return its output."""
    return subprocess.check_output(cmd, shell=True, text=True, timeout=30)


@mcp.tool
def host_uptime() -> str:
    """Return the host uptime."""
    return subprocess.check_output(["uptime"], text=True)


def serve() -> None:
    mcp.run(transport="http", host="0.0.0.0", port=8000)


def serve_authenticated() -> None:
    verifier = JWTVerifier(
        jwks_uri=os.environ["OIDC_JWKS_URI"],
        issuer=os.environ["OIDC_ISSUER"],
        audience="oracle-host",
    )
    secured = FastMCP("oracle-host-secured", auth=verifier)
    secured.add_tool(host_uptime)
    secured.run(transport="http", host="0.0.0.0", port=8443)


def proxy_openapi(spec_url: str) -> FastMCP:
    """Expose a partner's REST API as MCP tools from the spec URL they give us."""
    spec = httpx.get(spec_url, timeout=10).json()
    return FastMCP.from_openapi(spec, client=httpx.AsyncClient(base_url=spec["servers"][0]["url"]))


async def sampling_handler(
    messages: list[SamplingMessage], params: SamplingParams, context
) -> str:
    chat = [{"role": m.role, "content": m.content.text} for m in messages if m.content.type == "text"]
    if params.systemPrompt:
        chat.insert(0, {"role": "system", "content": params.systemPrompt})
    completion = openai_client.chat.completions.create(model="gpt-4o", messages=chat)
    return completion.choices[0].message.content or ""


async def call_peer(url: str, tool: str, arguments: dict) -> str:
    async with Client(url, sampling_handler=sampling_handler) as client:
        result = await client.call_tool(tool, arguments)
    return str(result.data)

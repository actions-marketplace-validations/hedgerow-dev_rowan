from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note."""
    return Path(path).read_text(encoding="utf-8")

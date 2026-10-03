from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("notes")
NOTES = Path("/srv/notes")


@mcp.tool()
def read_note(path: str) -> str:
    """Read a note."""
    return (NOTES / Path(path).name).read_text(encoding="utf-8")

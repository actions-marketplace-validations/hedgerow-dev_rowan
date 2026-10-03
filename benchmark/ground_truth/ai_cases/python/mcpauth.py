"""FastMCP 2 server on the http transport with no auth= (tnt-py-ai-mcpauth-001, CWE-306)."""

from fastmcp import FastMCP

mcp = FastMCP("notes")


@mcp.tool
def read_note(name: str) -> str:
    """Return a note by name."""
    return open(f"/srv/notes/{name}").read()


if __name__ == "__main__":
    mcp.run(transport="http", host="0.0.0.0", port=8000)

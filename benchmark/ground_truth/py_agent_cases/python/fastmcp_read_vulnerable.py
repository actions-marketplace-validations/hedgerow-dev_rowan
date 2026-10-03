from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace."""
    with open(path, encoding="utf-8") as handle:
        return handle.read()

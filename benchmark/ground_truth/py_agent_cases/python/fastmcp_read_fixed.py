import os

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("files")
WORKSPACE = os.path.realpath("/srv/workspace")


def resolve_in_workspace(path: str) -> str:
    resolved = os.path.realpath(os.path.join(WORKSPACE, path))
    if not resolved.startswith(WORKSPACE + os.sep):
        raise ValueError("path escapes the workspace")
    return resolved


@mcp.tool()
def read_file(path: str) -> str:
    """Read a file from the workspace."""
    with open(resolve_in_workspace(path), encoding="utf-8") as handle:
        return handle.read()

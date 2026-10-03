from mcp.server.fastmcp import FastMCP

from xf_py_helpers import disk_usage

mcp = FastMCP("ops")


@mcp.tool()
def usage(directory: str) -> str:
    """Report disk usage for a directory."""
    return disk_usage(directory)

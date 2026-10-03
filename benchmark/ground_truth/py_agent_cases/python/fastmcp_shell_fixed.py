import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_log(ref: str) -> str:
    """Show history for a ref."""
    return subprocess.run(["git", "log", "--oneline", "--", ref], capture_output=True, text=True).stdout

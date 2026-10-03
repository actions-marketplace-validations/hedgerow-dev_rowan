import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("git")


@mcp.tool()
def git_log(ref: str) -> str:
    """Show history for a ref."""
    return subprocess.run(f"git log --oneline {ref}", shell=True, capture_output=True, text=True).stdout

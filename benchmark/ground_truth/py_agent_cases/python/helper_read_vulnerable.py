from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("review")


def _read_for_inline(abs_path: str, limit: int) -> str:
    with Path(abs_path).open(encoding="utf-8", errors="ignore") as handle:
        return handle.read(limit)


@mcp.tool()
def consult_with_files(question: str, files: list[str]) -> str:
    """Ask a question about some files."""
    bodies = [_read_for_inline(name, 65536) for name in files]
    return question + "\n\n" + "\n".join(bodies)

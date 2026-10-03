from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("review")
ROOT = Path("/srv/project")


def _read_for_inline(name: str, limit: int) -> str:
    with (ROOT / Path(name).name).open(encoding="utf-8", errors="ignore") as handle:
        return handle.read(limit)


@mcp.tool()
def consult_with_files(question: str, files: list[str]) -> str:
    """Ask a question about some files."""
    bodies = [_read_for_inline(name, 65536) for name in files]
    return question + "\n\n" + "\n".join(bodies)

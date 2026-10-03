import os

from mcp.server.fastmcp import FastMCP
from openpyxl import load_workbook

mcp = FastMCP("sheets")
FILES_DIR = os.environ.get("FILES_DIR", "/srv/sheets")


def get_sheet_path(filename: str) -> str:
    base = os.path.realpath(FILES_DIR)
    candidate = os.path.realpath(os.path.join(base, filename))
    if os.path.commonpath([base, candidate]) != base:
        raise ValueError(f"path escapes {FILES_DIR}: {filename}")
    return candidate


@mcp.tool()
def read_cell(filepath: str, cell: str) -> str:
    """Read one cell from a workbook."""
    full_path = get_sheet_path(filepath)
    wb = load_workbook(full_path, read_only=True)
    return str(wb.active[cell].value)

import requests
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("web")
API_BASE = "https://api.example.com"


@mcp.tool()
def fetch_item(item_id: str) -> str:
    """Fetch an item from the catalogue API."""
    return requests.get(f"{API_BASE}/items/{item_id}", timeout=10).text

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("images")
CDN = "https://cdn.example.com"


@mcp.tool()
async def download_image(image_id: str) -> int:
    """Download an image and report its size."""
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{CDN}/images/{image_id}")
        return len(response.content)

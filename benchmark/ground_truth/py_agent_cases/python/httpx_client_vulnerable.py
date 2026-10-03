import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("images")


@mcp.tool()
async def download_image(image_url: str) -> int:
    """Download an image and report its size."""
    async with httpx.AsyncClient() as client:
        response = await client.get(image_url)
        return len(response.content)

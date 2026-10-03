from mcp.server.fastmcp import FastMCP

from xf_py_http import download_image

mcp = FastMCP("ads")


@mcp.tool()
async def upload_ad_image(image_url: str) -> int:
    """Upload an ad image."""
    data = await download_image(image_url)
    return len(data)

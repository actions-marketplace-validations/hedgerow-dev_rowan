from mcp.server.fastmcp import FastMCP

from xf_py_http import download_cdn_image

mcp = FastMCP("ads")


@mcp.tool()
async def upload_ad_image(image_id: str) -> int:
    """Upload an ad image."""
    data = await download_cdn_image(image_id)
    return len(data)

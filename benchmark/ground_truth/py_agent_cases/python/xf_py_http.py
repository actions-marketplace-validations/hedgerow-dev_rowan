import httpx

CDN = "https://cdn.example.com"


async def download_image(url: str) -> bytes:
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.content


async def download_cdn_image(image_id: str) -> bytes:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"{CDN}/images/{image_id}")
        return response.content

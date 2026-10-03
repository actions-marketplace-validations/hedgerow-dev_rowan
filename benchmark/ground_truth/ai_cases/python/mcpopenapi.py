"""FastMCP.from_openapi built from a request-controlled spec URL (tnt-py-ai-mcpopenapi-001, CWE-918)."""

import httpx
from fastapi import FastAPI
from fastmcp import FastMCP

app = FastAPI()


@app.post("/proxy")
def proxy(spec_url: str) -> dict:
    spec = httpx.get(spec_url, timeout=10).json()
    server = FastMCP.from_openapi(spec, client=httpx.AsyncClient(base_url=spec["servers"][0]["url"]))
    return {"name": server.name}

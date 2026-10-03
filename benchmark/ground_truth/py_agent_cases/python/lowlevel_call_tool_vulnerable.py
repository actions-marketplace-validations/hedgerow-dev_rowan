from mcp.server import Server
from mcp.types import TextContent

server = Server("notes")


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "read_note":
        with open(arguments["path"], encoding="utf-8") as handle:
            return [TextContent(type="text", text=handle.read())]
    raise ValueError(name)

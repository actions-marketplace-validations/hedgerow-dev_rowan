import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { validateUrl } from "./urls.js";

const server = new Server({ name: "web", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const url = validateUrl(String(request.params.arguments?.url));
  const response = await fetch(url);
  return { content: [{ type: "text", text: await response.text() }] };
});

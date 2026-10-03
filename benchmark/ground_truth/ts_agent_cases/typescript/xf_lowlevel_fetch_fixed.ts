import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { fetchArgsSafe } from "./xf_helpers.js";

const server = new Server({ name: "web", version: "1.0.0" }, { capabilities: { tools: {} } });

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const text = await fetchArgsSafe(request.params.arguments ?? {});
  return { content: [{ type: "text", text }] };
});

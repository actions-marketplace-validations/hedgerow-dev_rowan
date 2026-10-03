import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { diskUsage } from "./xf_helpers.js";

const server = new McpServer({ name: "ops", version: "1.0.0" });

server.tool("disk_usage", { dir: z.string() }, async ({ dir }) => {
  return { content: [{ type: "text", text: diskUsage(dir) }] };
});

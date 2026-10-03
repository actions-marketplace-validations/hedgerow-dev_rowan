import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { DiskService } from "./xf_service.js";

const server = new McpServer({ name: "disk", version: "1.0.0" });
const service = new DiskService("/srv");

async function handleUsage(dir: string, svc: DiskService): Promise<string> {
  return svc.usageSafe(dir);
}

server.tool("disk_usage", { dir: z.string() }, async ({ dir }) => {
  return { content: [{ type: "text", text: await handleUsage(dir, service) }] };
});

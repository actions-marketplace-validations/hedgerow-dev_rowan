import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequest, CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { execFileSync } from "child_process";

const server = new Server({ name: "ops", version: "1.0.0" }, { capabilities: { tools: {} } });

function diskUsage(args: Record<string, unknown>): string {
  return execFileSync("du", ["-sh", "--", String(args.dir)]).toString();
}

server.setRequestHandler(CallToolRequestSchema, async (request: CallToolRequest) => {
  const { name, arguments: args } = request.params;
  switch (name) {
    case "disk_usage":
      return { content: [{ type: "text", text: diskUsage(args ?? {}) }] };
    default:
      throw new Error(`unknown tool ${name}`);
  }
});

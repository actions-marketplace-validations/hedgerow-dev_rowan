import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFileSync } from "child_process";
import { z } from "zod";

const server = new McpServer({ name: "git", version: "1.0.0" });

server.registerTool(
  "git_log",
  { description: "Show history", inputSchema: { ref: z.string() } },
  async (args) => {
    const out = execFileSync("git", ["log", "--oneline", "--", args.ref]).toString();
    return { content: [{ type: "text", text: out }] };
  },
);

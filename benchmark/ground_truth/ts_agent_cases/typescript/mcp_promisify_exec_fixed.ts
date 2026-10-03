import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { execFile } from "child_process";
import { promisify } from "util";
import { z } from "zod";

const execFileAsync = promisify(execFile);
const server = new McpServer({ name: "users", version: "1.0.0" });

server.tool("user_info", { username: z.string() }, async ({ username }) => {
  const { stdout } = await execFileAsync("id", ["--", username]);
  return { content: [{ type: "text", text: stdout }] };
});

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import * as fs from "fs/promises";
import { z } from "zod";
import { validatePath } from "./paths.js";

const server = new McpServer({ name: "files", version: "1.0.0" });

server.tool("read_file", { path: z.string() }, async ({ path }) => {
  const allowed = await validatePath(path);
  const text = await fs.readFile(allowed, "utf8");
  return { content: [{ type: "text", text }] };
});

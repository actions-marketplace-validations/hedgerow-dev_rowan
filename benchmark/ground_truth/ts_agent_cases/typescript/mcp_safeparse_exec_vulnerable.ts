import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { CallToolRequestSchema } from "@modelcontextprotocol/sdk/types.js";
import { exec } from "child_process";
import { promisify } from "util";
import { z } from "zod";

const execAsync = promisify(exec);
const ScanSchema = z.object({ target: z.string() });
const server = new Server({ name: "scanner", version: "1.0.0" }, { capabilities: { tools: {} } });

async function runScan(params: z.infer<typeof ScanSchema>) {
  const { stdout } = await execAsync(`nmap -F ${params.target}`);
  return stdout;
}

server.setRequestHandler(CallToolRequestSchema, async (request) => {
  const parsed = ScanSchema.safeParse(request.params.arguments);
  if (!parsed.success) {
    throw new Error("invalid arguments");
  }
  const text = await runScan(parsed.data);
  return { content: [{ type: "text", text }] };
});

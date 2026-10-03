import { tool } from "ai";
import { execSync } from "child_process";
import { z } from "zod";

export const runCommand = tool({
  description: "Run a shell command in the workspace",
  inputSchema: z.object({ command: z.string() }),
  execute: async ({ command }) => execSync(command, { cwd: "/workspace" }).toString(),
});

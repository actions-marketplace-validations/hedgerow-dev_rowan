import { tool } from "ai";
import { execFileSync } from "child_process";
import { z } from "zod";

export const listDirectory = tool({
  description: "List a workspace directory",
  inputSchema: z.object({ dir: z.string() }),
  execute: async ({ dir }) => execFileSync("ls", ["-la", "--", dir], { cwd: "/workspace" }).toString(),
});

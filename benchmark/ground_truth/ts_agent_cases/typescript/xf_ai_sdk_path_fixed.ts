import { tool } from "ai";
import { z } from "zod";
import { readWorkspaceFileSafe } from "./xf_helpers.js";

export const readFile = tool({
  description: "Read a workspace file",
  inputSchema: z.object({ name: z.string() }),
  execute: async ({ name }) => readWorkspaceFileSafe(name),
});

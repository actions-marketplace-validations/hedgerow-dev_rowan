import { tool } from "@langchain/core/tools";
import * as fs from "fs";
import * as path from "path";
import { z } from "zod";

export const readNote = tool(
  async ({ filename }) => fs.readFileSync(path.join("/data/notes", path.basename(filename)), "utf8"),
  { name: "read_note", description: "Read a note", schema: z.object({ filename: z.string() }) },
);

import { tool } from "ai";
import { z } from "zod";

export const fetchPage = tool({
  description: "Fetch a web page",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    const response = await fetch(args.url);
    return response.text();
  },
});

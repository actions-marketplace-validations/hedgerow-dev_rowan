import { tool } from "ai";
import { z } from "zod";
import { validateUrl } from "./urls.js";

export const fetchPage = tool({
  description: "Fetch a web page",
  parameters: z.object({ url: z.string() }),
  execute: async (args) => {
    const response = await fetch(validateUrl(args.url));
    return response.text();
  },
});

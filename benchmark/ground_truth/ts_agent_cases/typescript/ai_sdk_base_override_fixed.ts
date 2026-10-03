import { tool } from "ai";
import { z } from "zod";

const apiUrl = process.env.API_URL ?? "https://api.internal.example";

export const apiRequest = tool({
  description: "Call the configured REST API",
  inputSchema: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    // Keep only the path and query; the host always comes from apiUrl.
    const { pathname, search } = new URL(path, "http://placeholder/");
    const response = await fetch(new URL(`${apiUrl}${pathname}${search}`));
    return response.json();
  },
});

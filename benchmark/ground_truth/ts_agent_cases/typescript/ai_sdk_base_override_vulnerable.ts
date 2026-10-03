import { tool } from "ai";
import { z } from "zod";

const apiUrl = process.env.API_URL ?? "https://api.internal.example";

export const apiRequest = tool({
  description: "Call the configured REST API",
  inputSchema: z.object({ path: z.string() }),
  execute: async ({ path }) => {
    // An absolute `path` such as http://169.254.169.254/ replaces the base host.
    const url = new URL(path, apiUrl);
    const response = await fetch(url);
    return response.json();
  },
});

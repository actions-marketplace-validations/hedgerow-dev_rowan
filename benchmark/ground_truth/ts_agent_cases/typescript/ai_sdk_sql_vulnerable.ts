import { tool } from "ai";
import { z } from "zod";
import { pool } from "./db.js";

export const lookupCustomer = tool({
  description: "Find a customer by name",
  inputSchema: z.object({ name: z.string() }),
  execute: async ({ name }) => {
    const result = await pool.query(`SELECT * FROM customers WHERE name = '${name}'`);
    return result.rows;
  },
});

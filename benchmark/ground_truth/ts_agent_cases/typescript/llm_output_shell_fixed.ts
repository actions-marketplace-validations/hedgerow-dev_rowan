import OpenAI from "openai";
import { execFileSync } from "child_process";

const client = new OpenAI();

export async function searchLogs(task: string): Promise<string> {
  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: `Give one grep pattern to ${task}` }],
  });
  const pattern = completion.choices[0].message.content ?? "";
  return execFileSync("grep", ["-rn", "--", pattern, "/var/log/app"]).toString();
}

import OpenAI from "openai";
import { execSync } from "child_process";

const client = new OpenAI();

export async function suggestAndRun(task: string): Promise<string> {
  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: `Give one shell command to ${task}` }],
  });
  const command = completion.choices[0].message.content ?? "";
  return execSync(command).toString();
}

import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

export async function calculate(question: string): Promise<unknown> {
  const { text } = await generateText({
    model: openai("gpt-4o-mini"),
    prompt: `Answer with a JSON number only: ${question}`,
  });
  return JSON.parse(text);
}

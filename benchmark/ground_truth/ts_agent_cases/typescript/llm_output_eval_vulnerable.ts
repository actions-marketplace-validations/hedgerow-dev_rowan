import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

export async function calculate(question: string): Promise<unknown> {
  const { text } = await generateText({
    model: openai("gpt-4o-mini"),
    prompt: `Write one JavaScript expression that answers: ${question}`,
  });
  return eval(text);
}

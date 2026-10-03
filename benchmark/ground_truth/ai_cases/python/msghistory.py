"""Pydantic AI agent.run with a request-controlled message_history (tnt-py-ai-msghistory-001, CWE-918)."""

from fastapi import FastAPI
from pydantic import BaseModel
from pydantic_ai import Agent
from pydantic_ai.messages import ModelMessagesTypeAdapter

app = FastAPI()
agent = Agent("openai:gpt-4o")


class Turn(BaseModel):
    prompt: str
    history: str


@app.post("/chat")
async def chat(turn: Turn) -> dict:
    history = ModelMessagesTypeAdapter.validate_json(turn.history)
    result = await agent.run(turn.prompt, message_history=history)
    return {"reply": result.output}

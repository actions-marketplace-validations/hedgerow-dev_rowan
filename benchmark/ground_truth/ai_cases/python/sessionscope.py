"""OpenAI Agents SQLiteSession keyed on a request-supplied id with no user scope (tnt-py-ai-sessionscope-001, CWE-639)."""

from agents import Agent, Runner, SQLiteSession
from fastapi import FastAPI

app = FastAPI()
agent = Agent(name="support", instructions="Help the customer with their order.")


@app.post("/chat")
def chat(session_id: str, text: str) -> dict:
    session = SQLiteSession(session_id, "conversations.db")
    result = Runner.run_sync(agent, text, session=session)
    return {"reply": result.final_output}

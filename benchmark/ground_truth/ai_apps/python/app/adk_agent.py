"""Metrics assistant on the Google Agent Development Kit."""

from __future__ import annotations

import os

from google.adk.agents import Agent
from google.adk.code_executors import UnsafeLocalCodeExecutor
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

APP_NAME = "oracle-metrics"


def disk_usage(mount: str) -> dict:
    """Report disk usage for a mount point."""
    output = os.popen(f"df -h {mount}").read()
    return {"mount": mount, "report": output}


metrics_agent = Agent(
    name="metrics",
    model="gemini-2.0-flash",
    instruction="Answer questions about host capacity. Use disk_usage for mount points.",
    tools=[disk_usage],
)

analyst_agent = Agent(
    name="analyst",
    model="gemini-2.0-flash",
    instruction="Write and run Python to answer numeric questions about the metrics tables.",
    code_executor=UnsafeLocalCodeExecutor(),
)

formula_agent = Agent(
    name="formula",
    model="gemini-2.0-flash",
    instruction=(
        "Turn the user's question into a single Python arithmetic expression over the "
        "variables cpu, mem and disk. Reply with the expression only."
    ),
)

session_service = InMemorySessionService()


async def run_agent(agent: Agent, user_id: str, session_id: str, user_text: str) -> str:
    runner = Runner(agent=agent, app_name=APP_NAME, session_service=session_service)
    await session_service.create_session(app_name=APP_NAME, user_id=user_id, session_id=session_id)
    content = types.Content(role="user", parts=[types.Part(text=user_text)])
    reply = ""
    async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
        if event.is_final_response() and event.content and event.content.parts:
            reply = event.content.parts[0].text or ""
    return reply


async def evaluate_formula(user_id: str, session_id: str, question: str, snapshot: dict) -> float:
    runner = Runner(agent=formula_agent, app_name=APP_NAME, session_service=session_service)
    content = types.Content(role="user", parts=[types.Part(text=question)])
    expression = ""
    async for event in runner.run_async(user_id=user_id, session_id=session_id, new_message=content):
        if event.content and event.content.parts:
            for part in event.content.parts:
                if part.text:
                    expression = part.text
    return float(eval(expression, {"__builtins__": {}}, dict(snapshot)))

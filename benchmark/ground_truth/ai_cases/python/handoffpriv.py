"""OpenAI Agents handoff to a child that holds a local ShellTool (tnt-py-ai-handoffpriv-001, CWE-269)."""

from agents import Agent, Runner, ShellTool
from agents.tool import LocalShellExecutor

ops = Agent(
    name="ops",
    instructions="Carry out the host operation you are handed.",
    tools=[ShellTool(executor=LocalShellExecutor())],
)

triage = Agent(
    name="triage",
    instructions="Answer questions yourself; hand host operations to ops.",
    handoffs=[ops],
)


def handle(user_text: str) -> str:
    return Runner.run_sync(triage, user_text).final_output

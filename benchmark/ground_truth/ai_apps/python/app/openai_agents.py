"""Ops assistant on the OpenAI Agents SDK."""

from __future__ import annotations

import subprocess

from agents import (
    Agent,
    GuardrailFunctionOutput,
    RunContextWrapper,
    Runner,
    ShellTool,
    SQLiteSession,
    function_tool,
    input_guardrail,
)
from agents.tool import LocalShellExecutor
from agents.tool_guardrails import (
    ToolGuardrailFunctionOutput,
    ToolInputGuardrailData,
    tool_input_guardrail,
)
from sqlalchemy import text

from .db import engine

ALLOWED_BINARIES = ("df", "uptime", "free", "who")


@function_tool
def run_shell(command: str) -> str:
    """Run a shell command on the ops host and return its output."""
    completed = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
    return completed.stdout or completed.stderr


ops_agent = Agent(
    name="ops",
    instructions="You help the on-call engineer inspect the host. Use run_shell when asked.",
    tools=[run_shell],
)


def ask_ops(user_text: str) -> str:
    result = Runner.run_sync(ops_agent, user_text)
    return result.final_output


sql_agent = Agent(
    name="sql-writer",
    instructions=(
        "Translate the user's question into a single SQLite SELECT over the "
        "tickets(id, title, body, owner) table. Reply with the SQL only."
    ),
)


def answer_with_sql(question: str) -> list[tuple]:
    result = Runner.run_sync(sql_agent, question)
    sql = result.final_output
    with engine.connect() as conn:
        rows = conn.execute(text(sql))
        return [tuple(row) for row in rows]


host_agent = Agent(
    name="host",
    instructions="Inspect the host with the shell tool and summarise what you find.",
    tools=[ShellTool(executor=LocalShellExecutor())],
)


def inspect_host(user_text: str) -> str:
    result = Runner.run_sync(host_agent, user_text)
    return result.final_output


# --- guarded variant -------------------------------------------------------


@input_guardrail
async def reject_destructive(
    ctx: RunContextWrapper, agent: Agent, user_input: str
) -> GuardrailFunctionOutput:
    lowered = user_input.lower()
    tripped = any(word in lowered for word in ("rm ", "mkfs", "shutdown", "dd "))
    return GuardrailFunctionOutput(output_info={"tripped": tripped}, tripwire_triggered=tripped)


@tool_input_guardrail
def allowlist_binary(data: ToolInputGuardrailData) -> ToolGuardrailFunctionOutput:
    command = str(data.context.tool_arguments.get("command", ""))
    binary = command.split()[0] if command.split() else ""
    if binary not in ALLOWED_BINARIES:
        return ToolGuardrailFunctionOutput.reject_content(f"{binary!r} is not an allowed binary")
    return ToolGuardrailFunctionOutput.allow()


@function_tool(tool_input_guardrails=[allowlist_binary])
def run_shell_guarded(command: str) -> str:
    """Run one of the read-only host inspection binaries."""
    completed = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
    return completed.stdout or completed.stderr


guarded_ops_agent = Agent(
    name="ops-guarded",
    instructions="You help the on-call engineer inspect the host using the allowed binaries only.",
    tools=[run_shell_guarded],
    input_guardrails=[reject_destructive],
)


def ask_ops_guarded(user_id: str, conversation_id: str, user_text: str) -> str:
    session = SQLiteSession(f"{user_id}:{conversation_id}", "conversations.db")
    result = Runner.run_sync(guarded_ops_agent, user_text, session=session)
    return result.final_output

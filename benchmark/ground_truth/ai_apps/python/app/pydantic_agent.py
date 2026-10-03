"""Knowledge-base assistant on Pydantic AI."""

from __future__ import annotations

import os
from pathlib import Path

import httpx
from pydantic import BaseModel
from pydantic_ai import Agent, RunContext
from pydantic_ai.messages import ModelMessage, ModelMessagesTypeAdapter

NOTES_ROOT = Path("/srv/oracle/notes")


class NotesDeps(BaseModel):
    workspace: str


notes_agent = Agent(
    "openai:gpt-4o",
    deps_type=NotesDeps,
    system_prompt="You answer questions from the workspace notes. Read files when needed.",
)


@notes_agent.tool
def read_note(ctx: RunContext[NotesDeps], path: str) -> str:
    """Return the text of a note by path."""
    with open(path) as fh:
        return fh.read()


@notes_agent.tool
def read_note_safe(ctx: RunContext[NotesDeps], path: str) -> str:
    """Return the text of a note, confined to the workspace directory."""
    base = (NOTES_ROOT / ctx.deps.workspace).resolve()
    target = (base / path).resolve()
    if not target.is_relative_to(base):
        raise ValueError("path escapes the workspace")
    return target.read_text()


@notes_agent.tool_plain
def rotate_logs(service: str) -> str:
    """Rotate the log files for a service."""
    os.system(f"logrotate -f /etc/logrotate.d/{service}")
    return f"rotated {service}"


def ask_notes(workspace: str, question: str) -> str:
    result = notes_agent.run_sync(question, deps=NotesDeps(workspace=workspace))
    return result.output


class ChatTurn(BaseModel):
    prompt: str
    history: str | None = None


async def continue_chat(turn: ChatTurn) -> str:
    history: list[ModelMessage] = []
    if turn.history:
        history = ModelMessagesTypeAdapter.validate_json(turn.history)
    result = await notes_agent.run(turn.prompt, message_history=history, deps=NotesDeps(workspace="default"))
    return result.output


citation_agent = Agent(
    "openai:gpt-4o",
    system_prompt="Given a claim, reply with the single best URL that supports it. URL only.",
)


def fetch_citation(claim: str) -> str:
    result = citation_agent.run_sync(claim)
    url = result.output
    response = httpx.get(url, timeout=10)
    return response.text[:2000]

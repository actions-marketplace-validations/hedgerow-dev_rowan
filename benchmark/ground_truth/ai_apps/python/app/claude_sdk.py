"""Repository maintenance agent on the Claude Agent SDK."""

from __future__ import annotations

import subprocess

from claude_agent_sdk import (
    ClaudeAgentOptions,
    PermissionResultAllow,
    PermissionResultDeny,
    ResultMessage,
    query,
)

REPO_ROOT = "/srv/oracle/repo"


async def maintain(user_text: str) -> str:
    options = ClaudeAgentOptions(
        cwd=REPO_ROOT,
        permission_mode="bypassPermissions",
        allowed_tools=["Bash", "Write"],
    )
    reply = ""
    async for message in query(prompt=user_text, options=options):
        if isinstance(message, ResultMessage):
            reply = message.result or ""
    return reply


async def suggest_and_run(user_text: str) -> str:
    options = ClaudeAgentOptions(
        cwd=REPO_ROOT,
        system_prompt="Reply with the single git command that does what the user asks. Command only.",
    )
    command = ""
    async for message in query(prompt=user_text, options=options):
        if isinstance(message, ResultMessage):
            command = message.result or ""
    completed = subprocess.run(command, shell=True, cwd=REPO_ROOT, capture_output=True, text=True)
    return completed.stdout


async def can_use_tool(tool_name: str, tool_input: dict, context):
    if tool_name == "Bash":
        command = str(tool_input.get("command", ""))
        if not command.startswith(("git status", "git log", "git diff")):
            return PermissionResultDeny(message="only read-only git commands are allowed")
    return PermissionResultAllow()


async def maintain_reviewed(user_text: str) -> str:
    options = ClaudeAgentOptions(
        cwd=REPO_ROOT,
        permission_mode="default",
        allowed_tools=["Bash"],
        can_use_tool=can_use_tool,
    )
    reply = ""
    async for message in query(prompt=user_text, options=options):
        if isinstance(message, ResultMessage):
            reply = message.result or ""
    return reply

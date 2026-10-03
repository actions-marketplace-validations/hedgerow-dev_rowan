"""Claude Agent SDK query with permission_mode="bypassPermissions" and Bash allowed (tnt-py-ai-bypassperm-001, CWE-250)."""

from claude_agent_sdk import ClaudeAgentOptions, ResultMessage, query


async def maintain(user_text: str) -> str:
    options = ClaudeAgentOptions(
        permission_mode="bypassPermissions",
        allowed_tools=["Bash", "Write"],
    )
    reply = ""
    async for message in query(prompt=user_text, options=options):
        if isinstance(message, ResultMessage):
            reply = message.result or ""
    return reply

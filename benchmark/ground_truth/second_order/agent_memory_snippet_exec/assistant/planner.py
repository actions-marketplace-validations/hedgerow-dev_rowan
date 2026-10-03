"""Planner turn.

Replays the conversation buffer, pulls the last fenced Python block out of
it, and evaluates it. The buffer was filled by `assistant.intake` on an
earlier request; there is no call edge between the two.
"""

import re

from langchain.memory import ConversationBufferMemory

from assistant.sandbox import evaluate_snippet

CODE_BLOCK_RE = re.compile(r"```python\n(.*?)```", re.DOTALL)

memory = ConversationBufferMemory(memory_key="history", return_messages=False)


def execute_last_plan():
    variables = memory.load_memory_variables({})
    history = variables["history"]

    blocks = CODE_BLOCK_RE.findall(history)
    if not blocks:
        return None

    return evaluate_snippet(blocks[-1])

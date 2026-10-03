"""LangGraph graph runs a model-written shell command with no interrupt() before it (tnt-py-ai-hitl-001, CWE-862)."""

import subprocess
from typing import TypedDict

from langchain_openai import ChatOpenAI
from langgraph.graph import END, START, StateGraph

model = ChatOpenAI(model="gpt-4o")


class State(TypedDict):
    request: str
    command: str
    output: str


def plan(state: State) -> State:
    reply = model.invoke(f"Write the shell command that does this: {state['request']}")
    return {**state, "command": reply.content.strip()}


def run(state: State) -> State:
    completed = subprocess.run(state["command"], shell=True, capture_output=True, text=True)
    return {**state, "output": completed.stdout}


graph = StateGraph(State)
graph.add_node("plan", plan)
graph.add_node("run", run)
graph.add_edge(START, "plan")
graph.add_edge("plan", "run")
graph.add_edge("run", END)
app = graph.compile()

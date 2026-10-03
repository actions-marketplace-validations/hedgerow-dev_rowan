"""Ticket-search and deploy agents on LangGraph."""

from __future__ import annotations

import sqlite3
import subprocess
from typing import TypedDict

from langchain_openai import ChatOpenAI
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph
from langgraph.prebuilt import create_react_agent
from langgraph.types import interrupt

model = ChatOpenAI(model="gpt-4o")
db = sqlite3.connect("oracle.db", check_same_thread=False)
checkpointer = SqliteSaver(sqlite3.connect("checkpoints.db", check_same_thread=False))


def run_query(term: str) -> list[tuple]:
    """Find tickets whose title mentions the term."""
    cursor = db.cursor()
    cursor.execute(f"SELECT id, title FROM tickets WHERE title LIKE '%{term}%'")
    return cursor.fetchall()


search_agent = create_react_agent(model, tools=[run_query], checkpointer=checkpointer)


def search_tickets(thread_id: str, question: str) -> str:
    config = {"configurable": {"thread_id": thread_id}}
    state = search_agent.invoke({"messages": [("user", question)]}, config=config)
    return state["messages"][-1].content


class DeployState(TypedDict):
    request: str
    command: str
    output: str


def plan_deploy(state: DeployState) -> DeployState:
    reply = model.invoke(
        f"Write the single shell command that performs this deployment request: {state['request']}"
    )
    return {**state, "command": reply.content.strip()}


def run_deploy(state: DeployState) -> DeployState:
    completed = subprocess.run(state["command"], shell=True, capture_output=True, text=True)
    return {**state, "output": completed.stdout}


def build_deploy_graph():
    graph = StateGraph(DeployState)
    graph.add_node("plan", plan_deploy)
    graph.add_node("run", run_deploy)
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "run")
    graph.add_edge("run", END)
    return graph.compile(checkpointer=checkpointer)


deploy_app = build_deploy_graph()


def deploy(thread_id: str, request: str) -> str:
    config = {"configurable": {"thread_id": thread_id}}
    state = deploy_app.invoke({"request": request, "command": "", "output": ""}, config=config)
    return state["output"]


# --- reviewed variant ------------------------------------------------------


def confirm_deploy(state: DeployState) -> DeployState:
    approved = interrupt({"question": "Run this command?", "command": state["command"]})
    if not approved:
        return {**state, "command": ""}
    return state


def run_reviewed_deploy(state: DeployState) -> DeployState:
    if not state["command"]:
        return {**state, "output": "declined"}
    completed = subprocess.run(state["command"], shell=True, capture_output=True, text=True)
    return {**state, "output": completed.stdout}


def build_reviewed_graph():
    graph = StateGraph(DeployState)
    graph.add_node("plan", plan_deploy)
    graph.add_node("confirm", confirm_deploy)
    graph.add_node("run", run_reviewed_deploy)
    graph.add_edge(START, "plan")
    graph.add_edge("plan", "confirm")
    graph.add_edge("confirm", "run")
    graph.add_edge("run", END)
    return graph.compile(checkpointer=checkpointer)


reviewed_deploy_app = build_reviewed_graph()


def deploy_reviewed(thread_id: str, request: str) -> str:
    config = {"configurable": {"thread_id": thread_id}}
    state = reviewed_deploy_app.invoke({"request": request, "command": "", "output": ""}, config=config)
    return state["output"]

"""Research desk services: search, triage and host maintenance."""

from __future__ import annotations

from agents import Agent, Runner, ShellTool
from agents.tool import LocalShellExecutor
from langchain_openai import ChatOpenAI
from langgraph.prebuilt import create_react_agent

from .toolkit import HostToolkit
from .tools import RESEARCH_TOOLS

model = ChatOpenAI(model="gpt-4o")

research_agent = create_react_agent(model, tools=RESEARCH_TOOLS)


def answer(question: str) -> str:
    state = research_agent.invoke({"messages": [("user", question)]})
    return state["messages"][-1].content


def build_ops_agent() -> Agent:
    return Agent(
        name="ops",
        instructions="Carry out the host operation the triage agent hands you.",
        tools=[ShellTool(executor=LocalShellExecutor())],
    )


def build_triage_agent() -> Agent:
    ops_agent = build_ops_agent()
    return Agent(
        name="triage",
        instructions="Decide whether the request is a question or a host operation. Hand operations to ops.",
        handoffs=[ops_agent],
    )


triage_agent = build_triage_agent()


def triage(user_text: str) -> str:
    result = Runner.run_sync(triage_agent, user_text)
    return result.final_output


def build_host_agent(host: str) -> Agent:
    toolkit = HostToolkit(host)
    return Agent(
        name="host-maintenance",
        instructions=f"Maintain services on {host} using the toolkit.",
        tools=toolkit.get_tools(),
    )


def maintain_host(host: str, user_text: str) -> str:
    result = Runner.run_sync(build_host_agent(host), user_text)
    return result.final_output

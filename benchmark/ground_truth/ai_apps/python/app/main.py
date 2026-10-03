"""Oracle service: FastAPI routes over the framework modules."""

from __future__ import annotations

from fastapi import Depends, FastAPI, Header
from pydantic import BaseModel

from . import adk_agent, claude_sdk, graph, mcp_server, openai_agents, pydantic_agent, sk, smol
from .db import fetch_ticket
from .research.routes import router as research_router

app = FastAPI(title="oracle")
app.include_router(research_router)


class Prompt(BaseModel):
    text: str


class ThreadPrompt(BaseModel):
    thread_id: str
    text: str


class SessionPrompt(BaseModel):
    session_id: str
    text: str


class NotesPrompt(BaseModel):
    workspace: str
    text: str


class ReportRequest(BaseModel):
    ticket_id: int
    template: str


class NoteSearch(BaseModel):
    query: str
    filter: str


class PeerCall(BaseModel):
    url: str
    tool: str
    arguments: dict


def current_user(x_user_id: str = Header(...)) -> str:
    return x_user_id


@app.post("/ops/ask")
def ops_ask(body: Prompt) -> dict:
    return {"reply": openai_agents.ask_ops(body.text)}


@app.post("/ops/ask-guarded")
def ops_ask_guarded(body: SessionPrompt, user: str = Depends(current_user)) -> dict:
    return {"reply": openai_agents.ask_ops_guarded(user, body.session_id, body.text)}


@app.post("/ops/sql")
def ops_sql(body: Prompt) -> dict:
    return {"rows": openai_agents.answer_with_sql(body.text)}


@app.post("/ops/host")
def ops_host(body: Prompt) -> dict:
    return {"reply": openai_agents.inspect_host(body.text)}


@app.post("/notes/ask")
def notes_ask(body: NotesPrompt) -> dict:
    return {"reply": pydantic_agent.ask_notes(body.workspace, body.text)}


@app.post("/notes/chat")
async def notes_chat(turn: pydantic_agent.ChatTurn) -> dict:
    return {"reply": await pydantic_agent.continue_chat(turn)}


@app.post("/notes/citation")
def notes_citation(body: Prompt) -> dict:
    return {"excerpt": pydantic_agent.fetch_citation(body.text)}


@app.post("/metrics/ask")
async def metrics_ask(body: SessionPrompt, user: str = Depends(current_user)) -> dict:
    return {"reply": await adk_agent.run_agent(adk_agent.metrics_agent, user, body.session_id, body.text)}


@app.post("/metrics/analyse")
async def metrics_analyse(body: SessionPrompt, user: str = Depends(current_user)) -> dict:
    return {"reply": await adk_agent.run_agent(adk_agent.analyst_agent, user, body.session_id, body.text)}


@app.post("/metrics/formula")
async def metrics_formula(body: SessionPrompt, user: str = Depends(current_user)) -> dict:
    snapshot = {"cpu": 0.42, "mem": 0.71, "disk": 0.55}
    value = await adk_agent.evaluate_formula(user, body.session_id, body.text, snapshot)
    return {"value": value}


@app.post("/data/analyse")
def data_analyse(body: Prompt) -> dict:
    return {"reply": smol.analyse(body.text)}


@app.post("/data/analyse-sandboxed")
def data_analyse_sandboxed(body: Prompt) -> dict:
    return {"reply": smol.analyse_sandboxed(body.text)}


@app.post("/data/snippet")
def data_snippet(body: Prompt) -> dict:
    return {"output": smol.run_snippet(body.text)}


@app.post("/tickets/search")
def tickets_search(body: ThreadPrompt) -> dict:
    return {"reply": graph.search_tickets(body.thread_id, body.text)}


@app.post("/deploy")
def deploy(body: ThreadPrompt) -> dict:
    return {"output": graph.deploy(body.thread_id, body.text)}


@app.post("/deploy-reviewed")
def deploy_reviewed(body: ThreadPrompt) -> dict:
    return {"output": graph.deploy_reviewed(body.thread_id, body.text)}


@app.post("/repo/maintain")
async def repo_maintain(body: Prompt) -> dict:
    return {"reply": await claude_sdk.maintain(body.text)}


@app.post("/repo/git")
async def repo_git(body: Prompt) -> dict:
    return {"output": await claude_sdk.suggest_and_run(body.text)}


@app.post("/repo/maintain-reviewed")
async def repo_maintain_reviewed(body: Prompt) -> dict:
    return {"reply": await claude_sdk.maintain_reviewed(body.text)}


@app.post("/reports/render")
async def reports_render(body: ReportRequest) -> dict:
    ticket = fetch_ticket(body.ticket_id) or {}
    return {"report": await sk.render_report(body.template, ticket)}


@app.post("/notes/search")
async def notes_search(body: NoteSearch) -> dict:
    return {"notes": await sk.search_notes(body.query, body.filter)}


@app.post("/mcp/proxy")
def mcp_proxy(body: Prompt) -> dict:
    proxied = mcp_server.proxy_openapi(body.text)
    return {"name": proxied.name}


@app.post("/mcp/peer")
async def mcp_peer(body: PeerCall) -> dict:
    return {"result": await mcp_server.call_peer(body.url, body.tool, body.arguments)}

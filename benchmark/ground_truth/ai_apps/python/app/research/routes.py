"""HTTP routes for the research desk."""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from . import service

router = APIRouter(prefix="/research")


class Question(BaseModel):
    question: str


class OpsRequest(BaseModel):
    text: str


class HostRequest(BaseModel):
    host: str
    text: str


@router.post("/ask")
def ask(body: Question) -> dict:
    return {"answer": service.answer(body.question)}


@router.post("/triage")
def triage(body: OpsRequest) -> dict:
    return {"result": service.triage(body.text)}


@router.post("/host")
def host(body: HostRequest) -> dict:
    return {"result": service.maintain_host(body.host, body.text)}

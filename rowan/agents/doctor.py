"""Preflight credential + connectivity checks for hunt's LLM backends.

Static checks (which env vars are set, which backend auto-detection would
prefer, whether a local server is reachable) cost nothing. The optional live
check sends one minimal completion to the resolved backend to confirm the
credential actually works, not just that it's present -- this does spend a
handful of tokens, so it's opt-in.

The `hunt` CLI defaults to `--backend auto` and uses the same
`LLMBackend.from_env()` selection reported here.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from rowan.agents.llm_backend import LLMBackend

# (backend name, env var name) -- checked in from_env()'s own priority order.
_CLOUD_CREDS: list[tuple[str, str]] = [
    ("deepseek", "DEEPSEEK_API_KEY"),
    ("openrouter", "OPENROUTER_API_KEY"),
    ("openai", "OPENAI_API_KEY"),
    ("alibaba", "ALIBABA_TOKEN_PLAN_API_KEY"),
]


@dataclass
class BackendCheck:
    backend: str
    configured: bool
    detail: str
    live_ok: bool | None = None  # None = not probed


@dataclass
class DoctorReport:
    selected_backend: str
    checks: list[BackendCheck] = field(default_factory=list)
    ollama_reachable: bool | None = None  # None = no local server checked

    @property
    def ok(self) -> bool:
        """True if the auto-detected backend is usable."""
        selected = next((c for c in self.checks if c.backend == self.selected_backend), None)
        if selected is None:
            return False
        if selected.live_ok is not None:
            return selected.live_ok
        return selected.configured

    def render(self) -> str:
        lines = ["hunt backend doctor"]
        for c in self.checks:
            marker = "->" if c.backend == self.selected_backend else "  "
            status = "configured" if c.configured else "not set"
            if c.live_ok is True:
                status += ", live check passed"
            elif c.live_ok is False:
                status += ", live check FAILED"
            lines.append(f"  {marker} {c.backend:11s}: {status}  ({c.detail})")
        lines.append("")
        lines.append(f"  auto-detected pick: {self.selected_backend}")
        lines.append("  note: `hunt --backend auto` uses this selection.")
        if self.ok:
            lines.append("  status: ready")
        else:
            lines.append("  status: NOT ready -- hunt will run static-only (no LLM triage)")
        return "\n".join(lines)


def _live_ok(text: str) -> bool:
    """A backend is live when it returned a non-empty completion that is not
    one of our own error strings (HN-19)."""
    return bool(text) and not text.startswith(("LLM error", "LLM not configured"))


def run_doctor(*, live: bool = False, timeout: int = 5) -> DoctorReport:
    """Check every LLM backend hunt knows about, plus which one auto-detection picks.

    Set live=True to send one minimal completion per configured cloud backend
    to confirm the credential is actually valid (spends a few tokens). Without
    it, cloud backends are only checked for "is an API key present" -- a set
    but invalid/expired key won't be caught until a real hunt run.
    """
    checks: list[BackendCheck] = []

    for name, env_var in _CLOUD_CREDS:
        configured = bool(os.environ.get(env_var, ""))
        check = BackendCheck(
            backend=name,
            configured=configured,
            detail=f"{env_var} {'set' if configured else 'unset'}",
        )
        if configured and live:
            # No explicit api_key needed -- LLMBackend reads os.environ live
            # at construction time.
            llm = LLMBackend(backend=name)
            response = llm.generate("ping", max_tokens=4)
            check.live_ok = _live_ok(response.text)
            if not response.text:
                check.detail += "; empty completion"
        checks.append(check)

    ollama = LLMBackend(backend="ollama")
    ollama_reachable = ollama.check_connectivity(timeout=timeout)
    checks.append(
        BackendCheck(
            backend="ollama",
            configured=ollama_reachable,
            detail=f"{ollama.base_url} {'reachable' if ollama_reachable else 'unreachable'}",
            live_ok=ollama_reachable if not live else None,
        )
    )
    if live and ollama_reachable:
        response = ollama.generate("ping", max_tokens=4)
        checks[-1].live_ok = _live_ok(response.text)
        if not response.text:
            checks[-1].detail += "; empty completion"

    selected = LLMBackend.from_env()

    return DoctorReport(
        selected_backend=selected._backend,
        checks=checks,
        ollama_reachable=ollama_reachable,
    )

"""Detect suspicious npm install-time lifecycle hooks.

``package.json`` ``scripts`` named ``preinstall`` / ``install`` /
``postinstall`` run automatically on ``npm install`` -- before any application
code executes and often on developer and CI machines with broad privileges.
This is the dominant npm supply-chain execution vector, and it is invisible to
source-code scanning (the payload lives in a JSON string, and frequently in a
*dependency's* package.json, not the app's own code).

Precision-first: the mere presence of an install hook is not flagged (husky,
node-gyp rebuilds, etc. are legitimate). A hook is only reported when its
command contains an actively suspicious construct -- a network fetch, a pipe
into an interpreter, an inline `eval`/`-e`/`-c`, or a base64-decode-to-shell.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_INSTALL_HOOKS = ("preinstall", "install", "postinstall")

# (compiled pattern, human-readable reason). Ordered most-to-least specific
# so the reported reason is the most informative match.
_SUSPICIOUS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:base64\s+-d|base64\s+--decode|atob)\b"), "base64-decoded payload"),
    (re.compile(r"\|\s*(?:sh|bash|zsh|node|python[0-9.]*)\b"), "pipes output into a shell/interpreter"),
    (re.compile(r"\b(?:curl|wget)\b"), "fetches a remote resource at install time"),
    (re.compile(r"https?://"), "contacts a remote URL at install time"),
    (re.compile(r"\bnode\s+-e\b"), "runs inline node code (node -e)"),
    (re.compile(r"\bpython[0-9.]*\s+-c\b"), "runs inline python code (python -c)"),
    (re.compile(r"\beval\b"), "calls eval"),
    (re.compile(r"process\.env\.[A-Za-z_]"), "reads environment variables"),
]


@dataclass(frozen=True)
class InstallHookFinding:
    hook: str          # preinstall / install / postinstall
    command: str       # the raw script command
    reason: str        # why it looks suspicious


def scan_install_hooks(package_json: dict) -> list[InstallHookFinding]:
    """Suspicious install-lifecycle hooks in a parsed ``package.json``."""
    scripts = package_json.get("scripts")
    if not isinstance(scripts, dict):
        return []

    findings: list[InstallHookFinding] = []
    for hook in _INSTALL_HOOKS:
        command = scripts.get(hook)
        if not isinstance(command, str) or not command.strip():
            continue
        for pattern, reason in _SUSPICIOUS:
            if pattern.search(command):
                findings.append(
                    InstallHookFinding(hook=hook, command=command.strip(), reason=reason)
                )
                break  # one reason per hook is enough
    return findings

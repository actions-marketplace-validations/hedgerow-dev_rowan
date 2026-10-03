"""RT-14: a taint sink with several named arguments must focus the payload.

`m($A, $B, ...)` without `focus-metavariable` fires when taint reaches any
argument, so a tainted HTTP method, getattr object or hub model name reads as
URL, attribute-name or repository injection. Each exception says why taint in
every named argument is the danger.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

RULES_DIR = Path(__file__).parent.parent / "rules"

_ALLOWED = {
    # Attacker config in either argument ends up in the merged result.
    "TNT-ML-003",
    # A tainted base directory is a traversal as much as a tainted leaf.
    "TNT-PATH-001",
}
_CALL_ARGS = re.compile(r"\(([^()]*)\)")
_METAVAR = re.compile(r"\$[A-Z_][A-Z0-9_]*")
_SKIP_KEYS = {"pattern-not", "pattern-not-inside", "pattern-inside", "metavariable-regex",
              "metavariable-pattern"}


def _multi_arg(pattern: str) -> bool:
    for match in _CALL_ARGS.finditer(pattern):
        args = [a.strip() for a in match.group(1).split(",")]
        if sum(bool(_METAVAR.fullmatch(a)) for a in args) >= 2:
            return True
    return False


def _unfocused(node, focused: bool = False) -> list[str]:
    found: list[str] = []
    if isinstance(node, list):
        for item in node:
            found += _unfocused(item, focused)
    elif isinstance(node, dict):
        if isinstance(node.get("patterns"), list):
            focused = focused or any(
                isinstance(x, dict) and "focus-metavariable" in x for x in node["patterns"]
            )
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                if not focused and _multi_arg(value):
                    found.append(value.strip())
            elif key not in _SKIP_KEYS:
                found += _unfocused(value, focused)
    return found


def test_multi_arg_sinks_focus():
    offenders = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules") or []:
            if rule.get("mode") != "taint" or rule["id"] in _ALLOWED:
                continue
            bad = _unfocused(rule.get("pattern-sinks", []))
            if bad:
                offenders[rule["id"]] = bad
    assert offenders == {}


def test_allowlist_names_real_unfocused_rules():
    """An exception that no longer needs to be one must be removed."""
    live = {}
    for path in sorted(RULES_DIR.glob("*.yaml")):
        for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get("rules") or []:
            if rule.get("mode") == "taint":
                live[rule["id"]] = _unfocused(rule.get("pattern-sinks", []))
    assert all(live.get(rule_id) for rule_id in _ALLOWED)

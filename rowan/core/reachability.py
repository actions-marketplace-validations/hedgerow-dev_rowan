"""Call-graph-based reachability for SCA findings.

Determines whether a vulnerable function from a flagged dependency is
actually invoked anywhere in the scanned codebase, via AST-verified,
import-alias-resolved function calls instead of a raw substring search.

This is intentionally narrower than full taint propagation: it answers
"is this function called anywhere in the repo" rather than "is it reachable
from a specific entry point with attacker-controlled data." That is still a
real precision improvement over substring matching, which flagged comments,
docstrings, and unrelated identically-named local functions as "reachable."

Python only for now -- see Rowan issue #24 for JS/TS scope.
"""

from __future__ import annotations

import ast
from pathlib import Path


def extract_import_aliases(tree: ast.AST) -> dict[str, str]:
    """Map each local name used in this file to its fully-qualified origin.

    import torch                        -> {"torch": "torch"}
    import torch as t                   -> {"t": "torch"}
    from torch import load              -> {"load": "torch.load"}
    from transformers import AutoModel  -> {"AutoModel": "transformers.AutoModel"}

    Relative imports (``from . import x``) are skipped -- they resolve to
    local modules, not third-party packages, so they can't carry a CVE.
    """
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local = alias.asname or alias.name.split(".")[0]
                aliases[local] = alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.module is None or node.level > 0:
                continue
            for alias in node.names:
                if alias.name == "*":
                    continue
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _dotted_call_name(node: ast.Call) -> str | None:
    """Reconstruct the dotted callee name of a call (e.g. 'torch.load')."""
    parts: list[str] = []
    cur = node.func
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    else:
        return None
    return ".".join(reversed(parts))


def resolve_calls(tree: ast.AST, aliases: dict[str, str]) -> set[str]:
    """Resolve every call expression in a file to a fully-qualified dotted name.

    A call is "resolved" when its leftmost name is a known import alias, so
    ``torch.load(...)`` becomes ``torch.load`` and ``load(...)`` (imported via
    ``from torch import load``) also becomes ``torch.load``. Calls whose
    receiver isn't a tracked import (local variables, builtins) are kept
    unqualified so package-prefix matching can still find direct module-level
    calls without false-resolving unrelated identifiers.
    """
    resolved: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        dotted = _dotted_call_name(node)
        if not dotted:
            continue
        head, _, rest = dotted.partition(".")
        if head in aliases:
            resolved.add(aliases[head] + (f".{rest}" if rest else ""))
        else:
            resolved.add(dotted)
    return resolved


def collect_reachable_calls(py_files: list[Path]) -> set[str]:
    """Walk a set of Python files and return the set of fully-qualified calls invoked."""
    all_calls: set[str] = set()
    for py_file in py_files:
        try:
            source = py_file.read_text(encoding="utf-8", errors="ignore")
            tree = ast.parse(source, filename=str(py_file))
        except (SyntaxError, UnicodeDecodeError, OSError):
            continue
        aliases = extract_import_aliases(tree)
        all_calls |= resolve_calls(tree, aliases)
    return all_calls


def is_package_reachable(
    package: str, vuln_funcs: list[str], resolved_calls: set[str]
) -> tuple[bool, str | None]:
    """Check whether the *specific* vulnerable function of ``package`` is called.

    Qualified entries (e.g. "torch.load") must match exactly in
    ``resolved_calls``.

    Bare entries (e.g. "from_pretrained") use a *scoped* suffix match: a
    resolved call must both (a) be qualified into this package's own
    namespace via real import aliasing, and (b) end with that method name --
    e.g. "transformers.AutoModelForCausalLM.from_pretrained" satisfies bare
    entry "from_pretrained" because HuggingFace exposes dozens of Auto*
    classes sharing this classmethod and enumerating them all isn't
    tractable. This is deliberately narrower than "any call into the
    package's namespace": ``torch.tensor(...)`` does NOT satisfy a bare
    "load" entry, because "tensor" doesn't end with ".load". Only the
    specific dangerous method name, on some member of the package, counts.
    """
    pkg_prefix = f"{package.lower()}."
    for entry in vuln_funcs:
        if "." in entry:
            if entry in resolved_calls:
                return True, entry
            continue
        suffix = f".{entry.lower()}"
        for call in resolved_calls:
            call_lower = call.lower()
            if call_lower.startswith(pkg_prefix) and call_lower.endswith(suffix):
                return True, call
    return False, None

"""MCP tool-metadata TOCTOU scanner (LangFail V59).

An MCP client approves a tool by the description / input schema advertised at
registration. If the server mutates that metadata after the tool object is
constructed, a later list_tools / invocation serves metadata the client never
approved -- the Invariant Labs "rug pull". TNT-ML-024 (rules/agent_taint.yaml)
catches an untrusted VALUE reaching a description at registration; this catches
the metadata being CHANGED after construction, a mutation across two program
points that single-point taint and line-regex cannot express.

Deliberately narrow for precision: it fires only on a reassignment of a
security-relevant metadata attribute (`description` / `inputSchema` /
`input_schema`) on a variable that was constructed from an MCP/agent Tool
constructor in the same module. A `.description =` on any other object, or on
a variable whose value did not come from a Tool constructor, is not tool
metadata and is left alone.
"""

from __future__ import annotations

import ast
import logging
from pathlib import Path

from rowan.core.findings import Category, Finding, Severity
from rowan.core.paths import iter_within_root

logger = logging.getLogger(__name__)

# Constructors whose result is an MCP / agent tool descriptor carrying the
# metadata a client approves. Matched on the call's last name, so `Tool(...)`,
# `types.Tool(...)` and `mcp.types.Tool(...)` all resolve.
_TOOL_CONSTRUCTORS = frozenset({"Tool", "FunctionTool", "StructuredTool"})

# The metadata fields a client trusts at approval time. `name` is excluded:
# renaming is a different (identity) concern and reassigning `.name` in
# builder code is common enough to be noisy.
_METADATA_FIELDS = frozenset({"description", "inputSchema", "input_schema"})

_SKIP_DIRS = frozenset({
    ".git", "node_modules", "venv", ".venv", "env",
    "__pycache__", ".tox", ".mypy_cache", ".pytest_cache",
    ".ruff_cache", "dist", "build", ".eggs",
})


def _call_last_name(func: ast.expr) -> str | None:
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _tool_vars(tree: ast.AST) -> set[str]:
    """Names assigned the result of a Tool constructor anywhere in the tree."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
            continue
        if _call_last_name(node.value.func) not in _TOOL_CONSTRUCTORS:
            continue
        for target in node.targets:
            if isinstance(target, ast.Name):
                names.add(target.id)
    return names


def _metadata_reassignments(tree: ast.AST, tool_vars: set[str]) -> list[tuple[int, str]]:
    """(line, field) for each reassignment of a metadata attribute on a tool
    variable -- both plain `t.description = ...` and augmented `t.description +=`."""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        targets: list[ast.expr] = []
        if isinstance(node, ast.Assign):
            targets = list(node.targets)
        elif isinstance(node, ast.AugAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if (
                isinstance(target, ast.Attribute)
                and target.attr in _METADATA_FIELDS
                and isinstance(target.value, ast.Name)
                and target.value.id in tool_vars
            ):
                hits.append((node.lineno, target.attr))
    return hits


def scan_file(path: Path) -> list[Finding]:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8", errors="ignore"), filename=str(path))
    except (SyntaxError, ValueError, OSError):
        return []
    return scan_tree(path, tree)


def scan_tree(path: Path, tree: ast.AST) -> list[Finding]:
    """Scan an already parsed tree, allowing a scan-owned snapshot to be reused."""

    tool_vars = _tool_vars(tree)
    if not tool_vars:
        return []
    findings: list[Finding] = []
    for line, field in _metadata_reassignments(tree, tool_vars):
        findings.append(
            Finding(
                rule_id="MCP-TOCTOU-001",
                message=(
                    f"An MCP tool's '{field}' is reassigned after the tool was "
                    f"constructed. A client approves a tool by the metadata it "
                    f"advertised at registration; changing it afterwards serves "
                    f"the client metadata it never reviewed (the tool-poisoning "
                    f"'rug pull'). Pin tool description and input schema to fixed "
                    f"literals set once at construction, reviewed with the code "
                    f"that grants the tool its capabilities."
                ),
                severity=Severity.HIGH,
                category=Category.AI_ML,
                file_path=str(path),
                start_line=line,
                confidence=0.8,
                engine="mcptoctou",
                cwe_ids=[367],
                metadata={"field": field},
            )
        )
    return findings


def scan_directory(
    target: Path, candidates: tuple[Path, ...] | None = None
) -> list[Finding]:
    target = Path(target)
    if candidates is not None:
        return [finding for path in candidates for finding in scan_file(path)]
    if target.is_file():
        return scan_file(target) if target.suffix == ".py" else []
    findings: list[Finding] = []
    for path in iter_within_root(target, "*.py"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        findings.extend(scan_file(path))
    return findings

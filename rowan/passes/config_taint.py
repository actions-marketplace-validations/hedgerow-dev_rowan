"""Detect user-writable configuration that controls security enforcement."""

from __future__ import annotations

import ast
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_SECURITY_KEY = re.compile(
    r"(?:security|auth|verify|validation|strict|safe|sandbox|tls|permission|allow)", re.I
)
_MERGE_CALLS = frozenset({"deep_merge", "merge", "merge_namespace", "merge_settings", "update"})
_GET_CALLS = frozenset({"get", "get_bool", "getboolean", "get_flag", "get_namespaced"})
_SANITIZERS = re.compile(r"(?:saniti[sz]e|validate|verify|check|normalise|normalize|resolve_safe)", re.I)


def _name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _render(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _literal(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _store_identity(call: ast.Call) -> str:
    dotted = _name(call.func)
    return dotted.rsplit(".", 1)[0] if "." in dotted else "__settings__"


def _request_tainted_names(fn: ast.AST) -> set[str]:
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
                text = _render(node.value)
                depends = "request." in text or any(
                    isinstance(child, ast.Name) and child.id in tainted
                    for child in ast.walk(node.value)
                )
                if not depends:
                    continue
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    for child in ast.walk(target):
                        if isinstance(child, ast.Name) and child.id not in tainted:
                            tainted.add(child.id)
                            changed = True
            elif isinstance(node, (ast.For, ast.AsyncFor)) and any(
                isinstance(child, ast.Name) and child.id in tainted
                for child in ast.walk(node.iter)
            ):
                for child in ast.walk(node.target):
                    if isinstance(child, ast.Name) and child.id not in tainted:
                        tainted.add(child.id)
                        changed = True
    return tainted


def _depends(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _allowlisted(fn: ast.AST, dynamic_name: str) -> bool:
    for node in ast.walk(fn):
        if not isinstance(node, ast.If) or not isinstance(node.test, ast.Compare):
            continue
        if not isinstance(node.test.left, ast.Name) or node.test.left.id != dynamic_name:
            continue
        if not any(isinstance(op, ast.NotIn) for op in node.test.ops):
            continue
        if any(
            isinstance(child, (ast.Return, ast.Raise, ast.Continue, ast.Break))
            for stmt in node.body for child in ast.walk(stmt)
        ):
            return True
    return False


@dataclass(frozen=True)
class _Writer:
    path: Path
    node: ast.Call
    store: str


@dataclass(frozen=True)
class _Decision:
    path: Path
    node: ast.If
    store: str
    key: str


class ConfigTaintPass:
    name = "config-taint"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        parsed = self._parse(context)
        writers: list[_Writer] = []
        decisions: list[_Decision] = []
        for path, tree in parsed:
            for fn in (
                node for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            ):
                writers.extend(self._writers(path, fn))
                decisions.extend(self._decisions(path, fn))

        findings: list[Finding] = []
        for writer in writers:
            compatible = [
                decision for decision in decisions
                if writer.store == decision.store
            ]
            for decision in compatible:
                findings.append(Finding(
                    rule_id="CONFIG-SECURITY-TAINT-001",
                    message=(
                        f"Configuration injection through an unrestricted deep-merge can "
                        f"change security toggle '{decision.key}', which conditionally controls "
                        "a validation or sanitizer step. Restrict writable namespaces and keys."
                    ),
                    severity=Severity.HIGH,
                    category=Category.CONFIG,
                    file_path=str(writer.path),
                    start_line=writer.node.lineno,
                    end_line=getattr(writer.node, "end_lineno", writer.node.lineno),
                    confidence=0.9,
                    cwe_ids=[15],
                    engine=self.name,
                    taint_flow=TaintFlow(
                        source=TaintNode(str(writer.path), writer.node.lineno),
                        sink=TaintNode(str(decision.path), decision.node.lineno),
                    ),
                    metadata={
                        "evidence_tier": "engine",
                        "config_store": writer.store,
                        "security_key": decision.key,
                        "security_decision_file": str(decision.path),
                    },
                ))
        result = ScanResult(findings=findings, files_scanned=len(parsed))
        duration = time.perf_counter() - started
        scan_span(self.name, duration)
        logger.info("ConfigTaintPass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _parse(self, context: ScanContext) -> list[tuple[Path, ast.Module]]:
        return list(iter_python_sources(context, owner=self.name, skip_tests=True))

    def _writers(self, path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef) -> list[_Writer]:
        tainted = _request_tainted_names(fn)
        writers: list[_Writer] = []
        for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
            terminal = _name(call.func).split(".")[-1]
            if terminal not in _MERGE_CALLS or not call.args:
                continue
            context = f"{path} {fn.name} {_name(call.func)}".lower()
            if "setting" not in context and "config" not in context:
                continue
            dynamic_args = [arg for arg in call.args[:2] if _depends(arg, tainted)]
            if not dynamic_args:
                continue
            namespace_names = {
                child.id for child in ast.walk(call.args[0])
                if isinstance(child, ast.Name) and child.id in tainted
            }
            if namespace_names and all(_allowlisted(fn, name) for name in namespace_names):
                continue
            literal_namespace = _literal(call.args[0])
            if literal_namespace is not None and not _SECURITY_KEY.search(literal_namespace):
                continue
            writers.append(_Writer(path, call, _store_identity(call)))
        return writers

    def _decisions(
        self, path: Path, fn: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> list[_Decision]:
        flags: dict[str, tuple[str, str]] = {}
        decisions: list[_Decision] = []
        for stmt in fn.body:
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                if not isinstance(stmt.value, ast.Call):
                    continue
                call = stmt.value
                if _name(call.func).split(".")[-1] not in _GET_CALLS or not call.args:
                    continue
                strings = [_literal(arg) for arg in call.args[:2]]
                key = ".".join(value for value in strings if value)
                if not key or not _SECURITY_KEY.search(key):
                    continue
                for target in targets:
                    if isinstance(target, ast.Name):
                        flags[target.id] = (_store_identity(call), key)
            elif isinstance(stmt, ast.If):
                used = next(
                    (name for name in flags if any(
                        isinstance(child, ast.Name) and child.id == name
                        for child in ast.walk(stmt.test)
                    )),
                    None,
                )
                if used is None:
                    continue
                if not any(
                    isinstance(call, ast.Call) and _SANITIZERS.search(_name(call.func))
                    for call in ast.walk(stmt)
                ):
                    continue
                store, key = flags[used]
                decisions.append(_Decision(path, stmt, store, key))
        return decisions

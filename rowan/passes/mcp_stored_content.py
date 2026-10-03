"""Detect low-privilege stored content crossing trusted MCP boundaries."""

from __future__ import annotations

import ast
import logging
import re
import time
from dataclasses import dataclass
from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)
_Func = ast.FunctionDef | ast.AsyncFunctionDef
_CONTENT_FIELD = re.compile(r"note|description|instruction|prompt|content|guidance", re.I)
_ADMIN_GATE = re.compile(r"admin|staff|superuser|permission", re.I)
_AUTH_GATE = re.compile(r"auth|login|required", re.I)
_SANITIZER = re.compile(r"saniti[sz]e|strip_directive|validate|moderate|filter|escape", re.I)


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


def _depends(node: ast.AST, names: set[str]) -> bool:
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _request_names(fn: _Func) -> set[str]:
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(fn):
            if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                continue
            if "request." not in _render(node.value) and not _depends(node.value, tainted):
                continue
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and child.id not in tainted:
                        tainted.add(child.id)
                        changed = True
    return tainted


@dataclass(frozen=True)
class _Writer:
    path: Path
    line: int
    model: str
    field: str


class MCPStoredContentPass:
    name = "mcp-stored-content"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        parsed = self._parse(context)
        writers = [writer for path, tree in parsed for writer in self._writers(path, tree)]
        metadata_consumers = self._metadata_consumers(parsed)
        findings: list[Finding] = []
        for writer in writers:
            for path, tree in parsed:
                findings.extend(self._sinks(writer, path, tree, metadata_consumers))
        result = ScanResult(findings=findings, files_scanned=len(parsed))
        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("MCPStoredContentPass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _parse(self, context: ScanContext) -> list[tuple[Path, ast.Module]]:
        return list(iter_python_sources(context, owner=self.name, skip_tests=True))

    def _writers(self, path: Path, tree: ast.Module) -> list[_Writer]:
        writers: list[_Writer] = []
        for fn in (node for node in ast.walk(tree) if isinstance(node, (_Func))):
            decorators = " ".join(_name(dec.func if isinstance(dec, ast.Call) else dec) for dec in fn.decorator_list)
            if not _AUTH_GATE.search(decorators) or _ADMIN_GATE.search(decorators):
                continue
            tainted = _request_names(fn)
            for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
                model = _name(call.func).split(".")[-1]
                for keyword in call.keywords:
                    if (
                        keyword.arg
                        and _CONTENT_FIELD.search(keyword.arg)
                        and ("request." in _render(keyword.value) or _depends(keyword.value, tainted))
                    ):
                        writers.append(_Writer(path, call.lineno, model, keyword.arg))
        return writers

    def _metadata_consumers(self, parsed: list[tuple[Path, ast.Module]]) -> set[str]:
        consumers: set[str] = set()
        for _path, tree in parsed:
            for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
                if not any(keyword.arg in {"description", "inputSchema", "input_schema"} for keyword in call.keywords):
                    continue
                for keyword in call.keywords:
                    if keyword.arg in {"description", "inputSchema", "input_schema"}:
                        consumers |= {
                            _name(child.func).split(".")[-1]
                            for child in ast.walk(keyword.value)
                            if isinstance(child, ast.Call)
                        }
        return consumers

    def _sinks(
        self,
        writer: _Writer,
        path: Path,
        tree: ast.Module,
        metadata_consumers: set[str],
    ) -> list[Finding]:
        findings: list[Finding] = []
        for fn in (node for node in ast.walk(tree) if isinstance(node, (_Func))):
            model_vars: set[str] = set()
            tainted: set[str] = set()
            changed = True
            while changed:
                changed = False
                for node in ast.walk(fn):
                    if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
                        continue
                    targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                    target_names = {
                        child.id for target in targets for child in ast.walk(target)
                        if isinstance(child, ast.Name)
                    }
                    value_text = _render(node.value)
                    if f"{writer.model}.query" in value_text or f"get({writer.model}" in value_text:
                        before = len(model_vars)
                        model_vars |= target_names
                        changed |= len(model_vars) != before
                    reads_field = any(
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id in model_vars
                        and child.attr == writer.field
                        for child in ast.walk(node.value)
                    )
                    if (reads_field or _depends(node.value, tainted)) and not _SANITIZER.search(value_text):
                        before = len(tainted)
                        tainted |= target_names
                        changed |= len(tainted) != before

            for call in (node for node in ast.walk(fn) if isinstance(node, ast.Call)):
                terminal = _name(call.func).split(".")[-1]
                if terminal in {"create_message", "sample"} and any(
                    _depends(arg, tainted) for arg in (*call.args, *(kw.value for kw in call.keywords))
                ):
                    findings.append(self._finding(
                        writer, path, call.lineno, "MCP-STORED-SAMPLING-001", 20,
                        "Broken authorization lets ordinary authenticated users store content that reaches an MCP sampling request without a human gate or content validation.",
                    ))
            metadata_returns = [
                ret
                for ret in ast.walk(fn)
                if isinstance(ret, ast.Return)
                and ret.value is not None
                and (
                    _depends(ret.value, tainted)
                    or any(
                        isinstance(child, ast.Attribute)
                        and isinstance(child.value, ast.Name)
                        and child.value.id in model_vars
                        and child.attr == writer.field
                        for child in ast.walk(ret.value)
                    )
                )
                and not _SANITIZER.search(_render(ret.value))
            ]
            if fn.name in metadata_consumers and metadata_returns:
                findings.append(self._finding(
                    writer, path, metadata_returns[0].lineno, "MCP-STORED-METADATA-AUTHZ-001", 862,
                    "Broken authorization lets ordinary authenticated users control server-authored MCP tool description metadata.",
                ))
        return findings

    def _finding(
        self, writer: _Writer, path: Path, line: int, rule_id: str, cwe: int, message: str
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            message=message,
            severity=Severity.HIGH,
            category=Category.AI_ML,
            file_path=str(path),
            start_line=line,
            confidence=0.9,
            cwe_ids=[cwe],
            engine=self.name,
            taint_flow=TaintFlow(
                source=TaintNode(str(writer.path), writer.line),
                sink=TaintNode(str(path), line),
            ),
            metadata={"model": writer.model, "field": writer.field, "writer_gate": "authenticated"},
        )

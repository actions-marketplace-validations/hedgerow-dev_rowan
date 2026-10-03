"""Detect uploaded source that becomes executable code on a later lifecycle event."""

from __future__ import annotations

import ast
import logging
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

_Func = ast.FunctionDef | ast.AsyncFunctionDef
_CODE_CONTEXT = ("plugin", "extension", "module", "addon", "hook")


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


def _parameters(fn: _Func) -> list[str]:
    return [
        arg.arg
        for arg in [*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs]
        if arg.arg not in {"self", "cls"}
    ]


def _depends_on(node: ast.AST, name: str) -> bool:
    return any(isinstance(item, ast.Name) and item.id == name for item in ast.walk(node))


def _request_derived(node: ast.AST, tainted: set[str]) -> bool:
    text = _render(node)
    if "request." in text and any(
        marker in text
        for marker in ("get_json", ".json", ".form", ".files", ".data", ".body")
    ):
        return True
    return any(isinstance(item, ast.Name) and item.id in tainted for item in ast.walk(node))


def _tainted_names(fn: _Func) -> set[str]:
    tainted: set[str] = set()
    changed = True
    while changed:
        changed = False
        for assign in (n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign))):
            if assign.value is None or not _request_derived(assign.value, tainted):
                continue
            targets = assign.targets if isinstance(assign, ast.Assign) else [assign.target]
            for target in targets:
                for child in ast.walk(target):
                    if isinstance(child, ast.Name) and child.id not in tainted:
                        tainted.add(child.id)
                        changed = True
    return tainted


@dataclass(frozen=True)
class _Function:
    path: Path
    node: _Func


@dataclass(frozen=True)
class _ArchiveLoader:
    path: Path
    name: str
    archive_params: frozenset[int]
    sink: ast.Call


class DormantCodePass:
    name = "dormant-code"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        functions = self._functions(context)
        by_name: dict[str, list[_Function]] = {}
        for function in functions:
            by_name.setdefault(function.node.name, []).append(function)

        writers = self._code_writers(functions)
        enabled_installers = self._enabled_installers(functions, writers)
        sources = self._request_sources(functions, enabled_installers)
        sinks = self._execution_sinks(functions)
        findings: list[Finding] = []
        if sources and sinks:
            for source_path, source_line, installer in sources:
                for sink_path, sink_node in sinks:
                    findings.append(Finding(
                        rule_id="LIFECYCLE-UPLOADED-CODE-001",
                        message=(
                            f"Request-controlled source is stored by '{installer}' as enabled "
                            "plugin/extension code and later loaded through exec_module() or "
                            "equivalent import machinery. Module-level code executes on the "
                            "later load or restart."
                        ),
                        severity=Severity.HIGH,
                        category=Category.SUPPLY_CHAIN,
                        file_path=str(sink_path),
                        start_line=sink_node.lineno,
                        end_line=getattr(sink_node, "end_lineno", sink_node.lineno),
                        start_column=getattr(sink_node, "col_offset", 0),
                        confidence=0.9,
                        cwe_ids=[829],
                        engine=self.name,
                        taint_flow=TaintFlow(
                            source=TaintNode(str(source_path), source_line),
                            sink=TaintNode(str(sink_path), sink_node.lineno),
                        ),
                        metadata={
                            "evidence_tier": "engine",
                            "lifecycle_boundary": "stored-now-executed-later",
                            "installer": installer,
                        },
                    ))
        archive_loaders = self._archive_loaders(functions)
        for source_path, source_line, loader in self._archive_request_sources(
            functions, archive_loaders
        ):
            findings.append(Finding(
                rule_id="IMPORTED-REPO-CODE-001",
                message=(
                    f"Request-controlled model/plugin repository archive reaches '{loader.name}', "
                    "which extracts the archive and executes imported source through "
                    "exec_module(). Treat repository code like an untrusted dependency: require "
                    "a reviewed publisher/signature and isolate execution."
                ),
                severity=Severity.HIGH,
                category=Category.SUPPLY_CHAIN,
                file_path=str(loader.path),
                start_line=loader.sink.lineno,
                end_line=getattr(loader.sink, "end_lineno", loader.sink.lineno),
                start_column=getattr(loader.sink, "col_offset", 0),
                confidence=0.95,
                cwe_ids=[829],
                engine=self.name,
                taint_flow=TaintFlow(
                    source=TaintNode(str(source_path), source_line),
                    sink=TaintNode(str(loader.path), loader.sink.lineno),
                ),
                metadata={
                    "evidence_tier": "engine",
                    "lifecycle_boundary": "archive-import-execution",
                    "loader": loader.name,
                },
            ))
        result = ScanResult(findings=findings, files_scanned=len({f.path for f in functions}))
        duration = time.perf_counter() - started
        scan_span(self.name, duration)
        logger.info("DormantCodePass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _functions(self, context: ScanContext) -> list[_Function]:
        out: list[_Function] = []
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=True):
            out.extend(
                _Function(path, node)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        return out

    def _code_writers(self, functions: list[_Function]) -> dict[str, set[int]]:
        writers: dict[str, set[int]] = {}
        for function in functions:
            params = _parameters(function.node)
            context = f"{function.path} {function.node.name} {_render(function.node)}".lower()
            if not any(marker in context for marker in _CODE_CONTEXT) and ".py" not in context:
                continue
            for call in (n for n in ast.walk(function.node) if isinstance(n, ast.Call)):
                terminal = _name(call.func).split(".")[-1]
                data_args: list[ast.AST] = []
                if terminal in {"write", "write_text", "write_bytes"} and call.args:
                    data_args = [call.args[0]]
                for index, param in enumerate(params):
                    if any(_depends_on(arg, param) for arg in data_args):
                        writers.setdefault(function.node.name, set()).add(index)
        return writers

    def _enabled_installers(
        self, functions: list[_Function], writers: dict[str, set[int]]
    ) -> dict[str, set[int]]:
        """Propagate writer parameters through wrappers that explicitly enable code."""
        installers: dict[str, set[int]] = {}
        changed = True
        while changed:
            changed = False
            targets = {**writers, **installers}
            for function in functions:
                params = _parameters(function.node)
                for call in (n for n in ast.walk(function.node) if isinstance(n, ast.Call)):
                    callee = _name(call.func).split(".")[-1]
                    if callee not in targets:
                        continue
                    enabled = any(
                        kw.arg in {"enabled", "active", "approved"}
                        and isinstance(kw.value, ast.Constant) and kw.value.value is True
                        for kw in call.keywords
                    )
                    if callee in writers and not enabled:
                        continue
                    for callee_index in targets[callee]:
                        if callee_index >= len(call.args):
                            continue
                        for index, param in enumerate(params):
                            if _depends_on(call.args[callee_index], param):
                                before = len(installers.setdefault(function.node.name, set()))
                                installers[function.node.name].add(index)
                                changed |= len(installers[function.node.name]) != before
        return installers

    def _request_sources(
        self, functions: list[_Function], installers: dict[str, set[int]]
    ) -> list[tuple[Path, int, str]]:
        sources: list[tuple[Path, int, str]] = []
        for function in functions:
            tainted = _tainted_names(function.node)
            for call in (n for n in ast.walk(function.node) if isinstance(n, ast.Call)):
                callee = _name(call.func).split(".")[-1]
                if callee not in installers:
                    continue
                if any(
                    index < len(call.args) and _request_derived(call.args[index], tainted)
                    for index in installers[callee]
                ):
                    sources.append((function.path, call.lineno, callee))
        return sources

    def _execution_sinks(self, functions: list[_Function]) -> list[tuple[Path, ast.Call]]:
        sinks: list[tuple[Path, ast.Call]] = []
        for function in functions:
            context = f"{function.path} {function.node.name}".lower()
            if not any(marker in context for marker in _CODE_CONTEXT):
                continue
            calls = [n for n in ast.walk(function.node) if isinstance(n, ast.Call)]
            executable = [call for call in calls if _name(call.func).endswith("exec_module")]
            loaders = [
                call for call in calls
                if _name(call.func).endswith(("spec_from_file_location", "SourceFileLoader"))
            ]
            chosen = executable[:1] or loaders[:1]
            sinks.extend((function.path, call) for call in chosen)
        return sinks

    def _archive_loaders(self, functions: list[_Function]) -> dict[str, list[_ArchiveLoader]]:
        """Functions that unpack a parameterized archive and import its source."""
        loaders: dict[str, list[_ArchiveLoader]] = {}
        for function in functions:
            params = _parameters(function.node)
            calls = [node for node in ast.walk(function.node) if isinstance(node, ast.Call)]
            sinks = [call for call in calls if _name(call.func).endswith("exec_module")]
            extracts = [
                call for call in calls
                if _name(call.func).split(".")[-1] in {
                    "extractall", "unpack_archive", "ZipFile", "TarFile", "open_archive",
                }
            ]
            if not sinks or not extracts:
                continue
            archive_params = frozenset(
                index
                for index, param in enumerate(params)
                if any(_depends_on(call, param) for call in extracts)
            )
            if not archive_params:
                continue
            loader = _ArchiveLoader(
                function.path, function.node.name, archive_params, sinks[0]
            )
            loaders.setdefault(function.node.name, []).append(loader)
        return loaders

    def _archive_request_sources(
        self,
        functions: list[_Function],
        loaders: dict[str, list[_ArchiveLoader]],
    ) -> list[tuple[Path, int, _ArchiveLoader]]:
        sources: list[tuple[Path, int, _ArchiveLoader]] = []
        for function in functions:
            tainted = _tainted_names(function.node)
            for call in (node for node in ast.walk(function.node) if isinstance(node, ast.Call)):
                candidates = loaders.get(_name(call.func).split(".")[-1], [])
                for loader in candidates:
                    if any(
                        index < len(call.args) and _request_derived(call.args[index], tainted)
                        for index in loader.archive_params
                    ):
                        sources.append((function.path, call.lineno, loader))
        return sources

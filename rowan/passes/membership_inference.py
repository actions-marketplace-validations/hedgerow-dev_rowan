"""Per-record membership-signal API detection (LF-6 / V56)."""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass

from rowan.analysis.request_sources import dotted_name, expr_reads_source, is_http_route
from rowan.analysis.stmt_walk import iter_body_statements
from rowan.analysis.summary_fixpoint import solve_summaries
from rowan.core.confidence import CROSSFILE_TAINT
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.cross_file import (
    _extract_imports,
    _ImportGraph,
    _resolve_call_target,
    _resolve_callee_file,
)
from rowan.passes.sources import iter_python_files, iter_python_sources

_RULE_ID = "ML-MEMBERSHIP-INFERENCE-001"
_RECORD_HINT = r"(?:record|row|sample|instance|example|member|membership|individual)"
_SIGNAL_HINT = r"(?:loss|confidence|score)"
_SIGNAL_RE = re.compile(
    rf"(?:{_RECORD_HINT}.*{_SIGNAL_HINT}|{_SIGNAL_HINT}.*{_RECORD_HINT})", re.I
)
_AGGREGATE_RE = re.compile(r"(?:batch|aggregate|mean|average|summary|dataset)", re.I)
_SIGNAL_RESPONSE_KEYS = {"loss", "confidence", "membership", "membership_score"}


@dataclass(frozen=True)
class _Summary:
    returns_signal: bool = False


def _is_signal_call(call: ast.Call) -> bool:
    tail = dotted_name(call.func).rsplit(".", 1)[-1]
    return bool(_SIGNAL_RE.search(tail)) and not bool(_AGGREGATE_RE.search(tail))


def _call_key(call, file, imports, functions):
    name, qualifier = _resolve_call_target(call)
    if not name:
        return None
    target = _resolve_callee_file(file, name, qualifier, imports)
    key = (target, name) if target else None
    return key if key in functions else None


def _analyze(file, func, imports, functions, summaries):
    signals: set[str] = set()

    def is_signal(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in signals
        if isinstance(expr, ast.Call):
            name = dotted_name(expr.func)
            if _AGGREGATE_RE.search(name) or name.rsplit(".", 1)[-1] in {"mean", "average"}:
                return False
            if _is_signal_call(expr):
                return True
            key = _call_key(expr, file, imports, functions)
            if key is not None and summaries[key].returns_signal:
                return True
        return any(is_signal(child) for child in ast.iter_child_nodes(expr))

    returns_signal = False
    for stmt in iter_body_statements(func.body):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            if is_signal(stmt.value):
                signals.add(stmt.targets[0].id)
            else:
                signals.discard(stmt.targets[0].id)
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            returns_signal |= is_signal(stmt.value)
    return _Summary(returns_signal)


class MembershipInferencePass:
    name = "membership_inference"

    @staticmethod
    def _python_files(context: ScanContext) -> list:
        """Compatibility wrapper for standalone callers and tests."""
        return list(iter_python_files(context, skip_tests=False))

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        imports = _ImportGraph()
        functions = {}
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            file = str(path.resolve())
            graph = _extract_imports(file, tree)
            imports.name_to_def.update(graph.name_to_def)
            imports.module_to_file.update(graph.module_to_file)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.setdefault((file, node.name), node)

        summaries = solve_summaries(
            functions,
            {key: _Summary() for key in functions},
            lambda call, key: _call_key(call, key[0], imports, functions),
            lambda key, current: _analyze(key[0], functions[key], imports, functions, current),
        )

        for key, func in functions.items():
            if not is_http_route(func):
                continue
            signals: set[str] = set()

            def exposed(expr: ast.AST, known: set[str], route_file: str) -> bool:
                if isinstance(expr, ast.Name):
                    return expr.id in known
                if isinstance(expr, ast.Call):
                    name = dotted_name(expr.func)
                    if _AGGREGATE_RE.search(name):
                        return False
                    if _is_signal_call(expr):
                        return True
                    callee = _call_key(expr, route_file, imports, functions)
                    if callee is not None and summaries[callee].returns_signal:
                        return True
                    if any(
                        kw.arg in _SIGNAL_RESPONSE_KEYS
                        and expr_reads_source(kw.value)
                        and not _AGGREGATE_RE.search(ast.unparse(kw.value))
                        for kw in expr.keywords
                    ):
                        return True
                return any(
                    exposed(child, known, route_file) for child in ast.iter_child_nodes(expr)
                )

            for stmt in iter_body_statements(func.body):
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    if exposed(stmt.value, signals, key[0]):
                        signals.add(stmt.targets[0].id)
                    else:
                        signals.discard(stmt.targets[0].id)
                if (
                    not isinstance(stmt, ast.Return)
                    or stmt.value is None
                    or not exposed(stmt.value, signals, key[0])
                ):
                    continue
                result.add_finding(Finding(
                    rule_id=_RULE_ID,
                    message=(
                        f"Inference endpoint '{func.name}' returns per-record loss, "
                        "confidence, or membership scores that can reveal whether an "
                        "individual record was present in model training data."
                    ),
                    severity=Severity.HIGH,
                    category=Category.AI_ML,
                    file_path=key[0],
                    start_line=stmt.lineno,
                    confidence=CROSSFILE_TAINT(1),
                    cwe_ids=[200],
                    owasp_ids=["API3:2023", "LLM02:2025"],
                    engine="membership_inference",
                    metadata={"endpoint": func.name, "signal": "per_record_loss_or_confidence"},
                ))
                break
        result.files_scanned = len({file for file, _ in functions})
        scan_span(self.name, time.perf_counter() - start)
        return result

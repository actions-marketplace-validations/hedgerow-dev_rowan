"""Training/retrieval data disclosure through model responses (LF-6 / V62)."""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass

from rowan.analysis.request_sources import dotted_name
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
from rowan.passes.sources import iter_python_sources

_RULE_ID = "TNT-ML-TRAINING-DISCLOSURE-001"
_TRAINING_STORE_RE = re.compile(r"(?:corpus|training|transcript)", re.I)
_PII_FIELDS = {
    "email", "ssn", "social_security_number", "dob", "date_of_birth",
    "phone", "phone_number", "address", "diagnosis", "medical_condition",
    "card_number", "passport_number",
}
_SANITIZER_RE = re.compile(r"(?:redact|mask|anonymi[sz]e|scrub|filter_pii)", re.I)
_ROUTE_TAILS = {"route", "get", "post", "put", "patch", "delete", "api_view"}


@dataclass(frozen=True)
class _Summary:
    returns_sensitive: bool = False
    response_sensitive: bool = False
    source_line: int = 0


def _is_route(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for dec in func.decorator_list:
        target = dec.func if isinstance(dec, ast.Call) else dec
        if dotted_name(target).rsplit(".", 1)[-1] in _ROUTE_TAILS:
            return True
    return False


def _unscoped_sensitive_read(call: ast.Call, training_models: set[str]) -> bool:
    rendered = ast.unparse(call)
    if not _TRAINING_STORE_RE.search(rendered) and not any(
        re.search(rf"\b{re.escape(name)}\b", rendered) for name in training_models
    ):
        return False
    if not any(token in rendered for token in (".query", ".objects", ".search(", ".similarity_search(")):
        return False
    return not bool(re.search(r"(?:owner|tenant|user|account)_id\s*=", rendered, re.I))


def _unscoped_orm_read(call: ast.Call) -> bool:
    rendered = ast.unparse(call)
    return (
        (
            ".query" in rendered
            or ".objects" in rendered
            or bool(re.search(r"(?:session|db)\.get\([A-Z]\w*", rendered))
        )
        and not re.search(r"(?:owner|tenant|user|account)_id\s*=", rendered, re.I)
    )


def _call_key(call, file, imports, functions):
    name, qualifier = _resolve_call_target(call)
    if not name:
        return None
    target = _resolve_callee_file(file, name, qualifier, imports)
    key = (target, name) if target else None
    return key if key in functions else None


def _analyze(file, func, imports, functions, summaries, training_models):
    sensitive: set[str] = set()
    retrieved: set[str] = set()
    source_line = 0

    def expr_sensitive(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in sensitive
        if (
            isinstance(expr, ast.Attribute)
            and expr.attr.lower() in _PII_FIELDS
            and isinstance(expr.value, ast.Name)
            and expr.value.id in retrieved
        ):
            return True
        if isinstance(expr, ast.Call):
            if _SANITIZER_RE.search(dotted_name(expr.func)):
                return False
            if _unscoped_sensitive_read(expr, training_models):
                return True
            key = _call_key(expr, file, imports, functions)
            if key is not None and summaries[key].returns_sensitive:
                return True
        return any(expr_sensitive(child) for child in ast.iter_child_nodes(expr))

    def reads_retrieved_pii(expr: ast.AST) -> bool:
        return any(
            isinstance(node, ast.Attribute)
            and node.attr.lower() in _PII_FIELDS
            and isinstance(node.value, ast.Name)
            and node.value.id in retrieved
            for node in ast.walk(expr)
        )

    returns_sensitive = False
    response_sensitive = False
    for stmt in iter_body_statements(func.body):
        for call in (node for node in ast.walk(stmt) if isinstance(node, ast.Call)):
            if _unscoped_sensitive_read(call, training_models) and not source_line:
                source_line = call.lineno
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            if isinstance(stmt.value, ast.Call) and _unscoped_orm_read(stmt.value):
                retrieved.add(stmt.targets[0].id)
            if expr_sensitive(stmt.value):
                sensitive.add(stmt.targets[0].id)
                if not source_line and reads_retrieved_pii(stmt.value):
                    source_line = stmt.lineno
            else:
                sensitive.discard(stmt.targets[0].id)
        elif isinstance(stmt, ast.AugAssign) and isinstance(stmt.target, ast.Name):
            if expr_sensitive(stmt.value):
                sensitive.add(stmt.target.id)
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            value_sensitive = expr_sensitive(stmt.value)
            returns_sensitive |= value_sensitive
            if value_sensitive and _is_route(func):
                response_sensitive = True

        for call in (node for node in ast.walk(stmt) if isinstance(node, ast.Call)):
            if dotted_name(call.func).rsplit(".", 1)[-1] in {
                "jsonify", "JsonResponse", "JSONResponse", "StreamingResponse", "send_json"
            } and any(expr_sensitive(x) for x in (*call.args, *(kw.value for kw in call.keywords))):
                response_sensitive = True
    return _Summary(returns_sensitive, response_sensitive, source_line)


class TrainingDisclosurePass:
    name = "training_disclosure"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        imports = _ImportGraph()
        functions = {}
        training_models: set[str] = set()
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            file = str(path.resolve())
            graph = _extract_imports(file, tree)
            imports.name_to_def.update(graph.name_to_def)
            imports.module_to_file.update(graph.module_to_file)
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    semantic_text = " ".join(
                        filter(None, (node.name, ast.get_docstring(node)))
                    )
                    if re.search(
                        r"(?:fine.?tun|training (?:data|example|record)|memorized|corpus|transcript)",
                        semantic_text,
                        re.I,
                    ):
                        training_models.add(node.name)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.setdefault((file, node.name), node)

        summaries = solve_summaries(
            functions,
            {key: _Summary() for key in functions},
            lambda call, key: _call_key(call, key[0], imports, functions),
            lambda key, current: _analyze(
                key[0], functions[key], imports, functions, current, training_models
            ),
        )

        callers = {key: set() for key in functions}
        for caller, node in functions.items():
            for call in (item for item in ast.walk(node) if isinstance(item, ast.Call)):
                callee = _call_key(call, caller[0], imports, functions)
                if callee is not None:
                    callers[callee].add(caller)

        response_nodes = {key for key, summary in summaries.items() if summary.response_sensitive}
        for key, summary in summaries.items():
            if not summary.source_line:
                continue
            reachable = {key}
            frontier = [key]
            while frontier:
                node = frontier.pop()
                for caller in callers[node] - reachable:
                    reachable.add(caller)
                    frontier.append(caller)
            endpoints = sorted({name for node, name in reachable & response_nodes})
            if not endpoints:
                continue
            result.add_finding(Finding(
                rule_id=_RULE_ID,
                message=(
                    "Unscoped memorized, training, or retrieved records flow into a "
                    f"client-visible model response through endpoint(s): {', '.join(endpoints)}."
                ),
                severity=Severity.HIGH,
                category=Category.AI_ML,
                file_path=key[0],
                start_line=summary.source_line,
                confidence=CROSSFILE_TAINT(2),
                cwe_ids=[200],
                owasp_ids=["LLM02:2025"],
                engine="training_disclosure",
                metadata={"source_function": key[1], "response_endpoints": endpoints},
            ))
        result.files_scanned = len({file for file, _ in functions})
        scan_span(self.name, time.perf_counter() - start)
        return result

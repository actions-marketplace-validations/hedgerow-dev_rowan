"""Full probability-vector API exposure detection (LF-6 / V55)."""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass

from rowan.analysis.request_sources import dotted_name, is_http_route
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

_RULE_ID = "ML-MODEL-EXTRACTION-001"
_VECTOR_CALLS = {
    "predict_proba", "predict_probabilities", "class_probabilities",
    "probability_vector", "decision_function", "predict_log_proba",
}
_REDUCER_RE = re.compile(r"(?:argmax|max|top_?k|predict_label|label_only|quantize|round_scores)", re.I)
_CONTROL_RE = re.compile(r"(?:rate.?limit|throttl|quota|query.?account|usage.?count|budget)", re.I)
_VECTOR_RESPONSE_KEYS = {"probabilities", "probability", "confidences", "scores", "logits"}


@dataclass(frozen=True)
class _Summary:
    returns_vector: bool = False


def _has_extraction_control(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    if any(
        _CONTROL_RE.search(dotted_name(dec.func if isinstance(dec, ast.Call) else dec))
        for dec in func.decorator_list
    ):
        return True
    return any(
        isinstance(node, ast.Call) and _CONTROL_RE.search(dotted_name(node.func))
        for node in ast.walk(func)
    )


def _call_key(call, file, imports, functions):
    name, qualifier = _resolve_call_target(call)
    if not name:
        return None
    target = _resolve_callee_file(file, name, qualifier, imports)
    key = (target, name) if target else None
    return key if key in functions else None


def _structural_vector(expr: ast.AST) -> bool:
    """Recognize full class-vector construction without relying on helper names."""
    if isinstance(expr, ast.Call):
        tail = dotted_name(expr.func).rsplit(".", 1)[-1].lower()
        if tail in {"softmax", "log_softmax"}:
            return True
        if tail == "dict" and any(
            isinstance(node, ast.Call)
            and dotted_name(node.func).rsplit(".", 1)[-1] == "zip"
            for node in ast.walk(expr)
        ):
            return True
    if isinstance(expr, ast.Dict):
        return any(
            isinstance(key, ast.Constant)
            and isinstance(key.value, str)
            and key.value.lower() in _VECTOR_RESPONSE_KEYS
            for key in expr.keys
        )
    return False


def _analyze(file, func, imports, functions, summaries):
    vectors: set[str] = set()

    def is_vector(expr: ast.AST) -> bool:
        if isinstance(expr, ast.Name):
            return expr.id in vectors
        if _structural_vector(expr):
            return True
        if isinstance(expr, ast.Call):
            name = dotted_name(expr.func)
            if _REDUCER_RE.search(name):
                return False
            if name.rsplit(".", 1)[-1] in _VECTOR_CALLS:
                return True
            key = _call_key(expr, file, imports, functions)
            if key is not None and summaries[key].returns_vector:
                return True
        if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Slice):
            # An explicit bounded slice is reduced output rather than the full vector.
            if isinstance(expr.slice.upper, ast.Constant) and isinstance(expr.slice.upper.value, int):
                return False
        return any(is_vector(child) for child in ast.iter_child_nodes(expr))

    returns_vector = False
    for stmt in iter_body_statements(func.body):
        if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
            if is_vector(stmt.value):
                vectors.add(stmt.targets[0].id)
            else:
                vectors.discard(stmt.targets[0].id)
        elif isinstance(stmt, ast.Return) and stmt.value is not None:
            returns_vector |= is_vector(stmt.value)
    return _Summary(returns_vector=returns_vector)


class ModelExtractionPass:
    name = "model_extraction"

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
            if not is_http_route(func) or _has_extraction_control(func):
                continue
            vectors: set[str] = set()

            def exposed(
                expr: ast.AST, known_vectors: set[str], route_file: str
            ) -> bool:
                if isinstance(expr, ast.Name):
                    return expr.id in known_vectors
                if _structural_vector(expr):
                    return True
                if isinstance(expr, ast.Call):
                    name = dotted_name(expr.func)
                    if _REDUCER_RE.search(name):
                        return False
                    if name.rsplit(".", 1)[-1] in _VECTOR_CALLS:
                        return True
                    callee = _call_key(expr, route_file, imports, functions)
                    if callee is not None and summaries[callee].returns_vector:
                        return True
                if isinstance(expr, ast.Subscript) and isinstance(expr.slice, ast.Slice):
                    if isinstance(expr.slice.upper, ast.Constant):
                        return False
                return any(
                    exposed(child, known_vectors, route_file)
                    for child in ast.iter_child_nodes(expr)
                )

            for stmt in iter_body_statements(func.body):
                if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and isinstance(stmt.targets[0], ast.Name):
                    if exposed(stmt.value, vectors, key[0]):
                        vectors.add(stmt.targets[0].id)
                    else:
                        vectors.discard(stmt.targets[0].id)
                if (
                    not isinstance(stmt, ast.Return)
                    or stmt.value is None
                    or not exposed(stmt.value, vectors, key[0])
                ):
                    continue
                result.add_finding(Finding(
                    rule_id=_RULE_ID,
                    message=(
                        f"Inference endpoint '{func.name}' returns a full per-class "
                        "probability/confidence vector without visible query accounting "
                        "or rate limiting, enabling model extraction."
                    ),
                    severity=Severity.HIGH,
                    category=Category.AI_ML,
                    file_path=key[0],
                    start_line=stmt.lineno,
                    confidence=CROSSFILE_TAINT(1),
                    cwe_ids=[200],
                    owasp_ids=["API3:2023", "LLM02:2025"],
                    engine="model_extraction",
                    metadata={"endpoint": func.name, "missing_controls": ["query_accounting", "rate_limit"]},
                ))
                break
        result.files_scanned = len({file for file, _ in functions})
        scan_span(self.name, time.perf_counter() - start)
        return result

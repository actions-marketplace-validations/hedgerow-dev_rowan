"""Detect unreviewed feedback records entering model-training operations."""

from __future__ import annotations

import ast
import logging
import re
import time
from pathlib import Path

from rowan.analysis.stmt_walk import iter_body_statements
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_RULE_ID = "ML-UNREVIEWED-TRAINING-001"
_APPROVED = re.compile(r"\b(?:approved|reviewed|accepted|verified|moderated)\b", re.I)
_REVIEW_FIELD = re.compile(r"\b(?:status|state|approved|reviewed|moderated)\b", re.I)
_FEEDBACK_MODEL = re.compile(r"(?:feedback|correction|review|submission|annotation)", re.I)
_TRAINING_SINKS = frozenset({
    "apply_feedback", "fit", "fit_transform", "fine_tune", "finetune", "partial_fit",
    "retrain", "train", "train_on_batch", "update_model",
})


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


def _approval_filtered(node: ast.AST) -> bool:
    text = _render(node)
    return bool(_REVIEW_FIELD.search(text) and _APPROVED.search(text))


def _assigned_names(stmt: ast.Assign | ast.AnnAssign) -> set[str]:
    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
    return {
        child.id
        for target in targets
        for child in ast.walk(target)
        if isinstance(child, ast.Name)
    }


class TrainingApprovalPass:
    name = "training-approval"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        parsed = self._parse(context)
        feedback_models = self._feedback_models(parsed)
        findings: list[Finding] = []
        if feedback_models:
            for path, tree in parsed:
                for function in (
                    node for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                ):
                    finding = self._scan_function(path, function, feedback_models)
                    if finding is not None:
                        findings.append(finding)
        result = ScanResult(findings=findings, files_scanned=len(parsed))
        duration = time.perf_counter() - started
        scan_span(self.name, duration)
        logger.info("TrainingApprovalPass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _parse(self, context: ScanContext) -> list[tuple[Path, ast.Module]]:
        return list(iter_python_sources(context, owner=self.name, skip_tests=True))

    def _feedback_models(self, parsed: list[tuple[Path, ast.Module]]) -> set[str]:
        models: set[str] = set()
        for _path, tree in parsed:
            for cls in (node for node in ast.walk(tree) if isinstance(node, ast.ClassDef)):
                fields = {
                    target.id
                    for stmt in cls.body
                    if isinstance(stmt, (ast.Assign, ast.AnnAssign))
                    for target in (
                        stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    )
                    if isinstance(target, ast.Name)
                }
                semantic = " ".join((cls.name, ast.get_docstring(cls) or ""))
                has_payload = bool(fields & {"features", "label", "correction", "content", "text"})
                has_review = bool(fields & {"status", "state", "approved", "reviewed", "moderated"})
                if _FEEDBACK_MODEL.search(semantic) and has_payload and has_review:
                    models.add(cls.name)
        return models

    def _scan_function(
        self,
        path: Path,
        function: ast.FunctionDef | ast.AsyncFunctionDef,
        feedback_models: set[str],
    ) -> Finding | None:
        unsafe_rows: dict[str, int] = {}
        for stmt in iter_body_statements(function.body):
            if isinstance(stmt, (ast.For, ast.AsyncFor)):
                source_names = {
                    node.id for node in ast.walk(stmt.iter)
                    if isinstance(node, ast.Name) and node.id in unsafe_rows
                }
                if source_names and not _approval_filtered(stmt):
                    source_line = min(unsafe_rows[name] for name in source_names)
                    for node in ast.walk(stmt.target):
                        if isinstance(node, ast.Name):
                            unsafe_rows[node.id] = source_line
            if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
                names = _assigned_names(stmt)
                text = _render(stmt.value)
                reads_feedback = any(
                    re.search(rf"\b{re.escape(model)}\b", text) for model in feedback_models
                ) and any(marker in text for marker in (".query", ".objects", ".select", ".all("))
                derives_rows = any(
                    isinstance(node, ast.Name) and node.id in unsafe_rows
                    for node in ast.walk(stmt.value)
                )
                if _approval_filtered(stmt.value):
                    for name in names:
                        unsafe_rows.pop(name, None)
                elif reads_feedback:
                    for name in names:
                        unsafe_rows[name] = stmt.lineno
                elif derives_rows:
                    source_line = min(
                        unsafe_rows[node.id]
                        for node in ast.walk(stmt.value)
                        if isinstance(node, ast.Name) and node.id in unsafe_rows
                    )
                    for name in names:
                        unsafe_rows[name] = source_line

            for call in (node for node in ast.walk(stmt) if isinstance(node, ast.Call)):
                if _name(call.func).split(".")[-1] not in _TRAINING_SINKS:
                    continue
                used = {
                    node.id
                    for arg in [*call.args, *(kw.value for kw in call.keywords)]
                    for node in ast.walk(arg)
                    if isinstance(node, ast.Name) and node.id in unsafe_rows
                }
                if not used:
                    continue
                source_line = min(unsafe_rows[name] for name in used)
                return Finding(
                    rule_id=_RULE_ID,
                    message=(
                        "ML supply chain: feedback, correction, or review records enter model "
                        "training without an approved/reviewed-state filter. Pending attacker "
                        "submissions can poison learned behavior or introduce a targeted backdoor."
                    ),
                    severity=Severity.HIGH,
                    category=Category.AI_ML,
                    file_path=str(path),
                    start_line=source_line,
                    end_line=getattr(call, "end_lineno", call.lineno),
                    confidence=0.9,
                    cwe_ids=[829],
                    owasp_ids=["ML06:2023"],
                    engine=self.name,
                    metadata={
                        "evidence_tier": "engine",
                        "training_function": function.name,
                        "training_sink": _name(call.func),
                        "unreviewed_variables": sorted(used),
                    },
                )
        return None

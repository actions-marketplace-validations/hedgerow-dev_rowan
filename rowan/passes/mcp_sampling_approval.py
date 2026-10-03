"""Structural detection of MCP client sampling callbacks without human review.

The low-level MCP Python SDK registers the client-side handler through
``Client(..., sampling_callback=...)`` or ``ClientSession(...,
sampling_callback=...)``.  A line regex cannot reliably connect that
registration to a purpose-named callback such as ``decide_server_request``.
"""

from __future__ import annotations

import ast
import logging
import re
import time
from pathlib import Path

from rowan.analysis.request_sources import dotted_name
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_RULE_ID = "MCP-SAMPLING-APPROVAL-001"
_REVIEW_CALL_RE = re.compile(
    r"(?:input|confirm|approve|review|prompt_user|ask_user|user_confirm|request_approval)",
    re.IGNORECASE,
)


class MCPSamplingApprovalPass:
    """Find registered MCP sampling callbacks lacking a visible review step.

    The pass only follows literal same-module callback names supplied to an
    imported MCP client constructor.  It deliberately does not treat an
    arbitrary ``create_message`` call or a purpose-named function as proof of
    a host approval path.
    """

    name = "mcp-sampling-approval"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        findings: list[Finding] = []
        files_scanned = 0
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=True):
            files_scanned += 1
            findings.extend(self._scan_file(path, tree))

        result = ScanResult(findings=findings, files_scanned=files_scanned)
        duration = time.perf_counter() - started
        scan_span(self.name, duration)
        logger.info("MCPSamplingApprovalPass: %d finding(s) in %.2fs", len(findings), duration)
        return result

    def _scan_file(self, path: Path, tree: ast.Module) -> list[Finding]:
        client_names = self._mcp_client_names(tree)
        if not client_names:
            return []
        callbacks = {
            node.name: node
            for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        }
        findings: list[Finding] = []
        reported: set[str] = set()
        for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
            if dotted_name(call.func) not in client_names:
                continue
            callback = next(
                (keyword.value for keyword in call.keywords if keyword.arg == "sampling_callback"),
                None,
            )
            if not isinstance(callback, ast.Name) or callback.id in reported:
                continue
            handler = callbacks.get(callback.id)
            if handler is None or self._has_human_review(handler):
                continue
            reported.add(callback.id)
            findings.append(self._make_finding(path, handler, callback.id))
        return findings

    @staticmethod
    def _mcp_client_names(tree: ast.Module) -> set[str]:
        names: set[str] = set()
        mcp_modules: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name == "mcp":
                        mcp_modules.add(alias.asname or alias.name)
            elif isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("mcp"):
                names.update(
                    alias.asname or alias.name
                    for alias in node.names
                    if alias.name in {"Client", "ClientSession"}
                )
        for module in mcp_modules:
            names.update(
                {
                    f"{module}.Client",
                    f"{module}.client.Client",
                    f"{module}.client.session.ClientSession",
                }
            )
        return names

    @staticmethod
    def _has_human_review(handler: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any(
            isinstance(node, ast.Call) and _REVIEW_CALL_RE.search(dotted_name(node.func))
            for node in ast.walk(handler)
        )

    @staticmethod
    def _make_finding(
        path: Path, handler: ast.FunctionDef | ast.AsyncFunctionDef, callback_name: str
    ) -> Finding:
        return Finding(
            rule_id=_RULE_ID,
            message=(
                f"MCP sampling callback '{callback_name}' is registered without a visible "
                "human-review call. Require explicit user approval before returning a "
                "sampling result to the server."
            ),
            severity=Severity.INFO,
            category=Category.AI_ML,
            file_path=str(path),
            start_line=handler.lineno,
            end_line=getattr(handler, "end_lineno", handler.lineno),
            start_column=getattr(handler, "col_offset", 0),
            confidence=0.65,
            cwe_ids=[862],
            engine="mcp-sampling-approval",
            metadata={"evidence_tier": "engine", "structural_evidence": True},
        )

"""Structural cross-file checks for agent resource and Markdown egress flows."""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass
from pathlib import Path

from rowan.analysis.request_sources import dotted_name
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.llm_sources import LLM_COMPLETION_RE
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

_LLM_CALL_RE = re.compile(r"(?:chat|completion|generate|invoke|predict)$", re.I)
# A bare `render` (a Django widget, a template view) is not a Markdown
# renderer; the name or the module's imports must say Markdown (AZ-18).
_MARKDOWN_NAME_RE = re.compile(r"markdown|(?:^|_)md(?:_|$)", re.I)
_MARKDOWN_MODULES = {"markdown", "mistune", "markdown_it", "commonmark"}
_IMAGE_TEMPLATE_RE = re.compile(r"<img\b[^>]*\bsrc\s*=", re.I)
_SAFE_IMAGE_RE = re.compile(r"(?:src|url|href)\.startswith\([^)]*(?:allow|safe|origin)", re.I)
_ROUTE_TAILS = {"route", "api_route", "get", "post", "put", "patch", "delete", "api_view"}


@dataclass(frozen=True)
class _Function:
    path: Path
    node: ast.FunctionDef | ast.AsyncFunctionDef
    module: ast.Module


def _call_tail(node: ast.AST) -> str:
    return dotted_name(node).rsplit(".", 1)[-1]


def _is_llm_call(call: ast.Call) -> bool:
    """`*.create` counts only in an LLM SDK shape (`chat.completions.create`,
    `messages.create`); `Item.objects.create` is an ORM write (AZ-18)."""
    name = dotted_name(call.func)
    if name.rsplit(".", 1)[-1].lower() == "create":
        return bool(LLM_COMPLETION_RE.search("." + name))
    return bool(_LLM_CALL_RE.search(_call_tail(call.func)))


def _imports_markdown(module: ast.Module) -> bool:
    for node in module.body:
        if isinstance(node, ast.Import):
            names = [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.module:
            names = [node.module]
        else:
            continue
        if any(name.split(".", 1)[0] in _MARKDOWN_MODULES for name in names):
            return True
    return False


def _assigned_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Assign):
        return {target.id for target in node.targets if isinstance(target, ast.Name)}
    if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
        return {node.target.id}
    return set()


def _is_route(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    return any(
        _call_tail(dec.func if isinstance(dec, ast.Call) else dec) in _ROUTE_TAILS
        for dec in node.decorator_list
    )


def _request_expr(node: ast.AST, containers: set[str], tainted: set[str]) -> bool:
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.Call):
        receiver = dotted_name(node.func.value) if isinstance(node.func, ast.Attribute) else ""
        if receiver.startswith("request."):
            return True
        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and receiver in containers
        ):
            return True
        return any(
            _request_expr(arg, containers, tainted)
            for arg in (*node.args, *(kw.value for kw in node.keywords))
        )
    return any(_request_expr(child, containers, tainted) for child in ast.iter_child_nodes(node))


class AgentFlowPass:
    """Detect caller-controlled agent budgets and unsafe custom Markdown renderers."""

    name = "agent-flow"

    def run(self, context: ScanContext) -> ScanResult:
        started = time.perf_counter()
        functions = self._functions(context)
        result = ScanResult(files_scanned=len({item.path for item in functions}))
        budget_sinks = self._budget_sinks(functions)
        for func in functions:
            result.findings.extend(self._budget_findings(func, budget_sinks))
            result.findings.extend(self._markdown_findings(func))
        scan_span(self.name, time.perf_counter() - started)
        return result

    def _functions(self, context: ScanContext) -> list[_Function]:
        result: list[_Function] = []
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=True):
            result.extend(
                _Function(path, node, tree)
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            )
        return result

    @staticmethod
    def _budget_sinks(functions: list[_Function]) -> dict[str, dict[Path, set[tuple[int, str]]]]:
        sinks: dict[str, dict[Path, set[tuple[int, str]]]] = {}
        for func in functions:
            params = [
                arg.arg
                for arg in (*func.node.args.posonlyargs, *func.node.args.args)
                if arg.arg not in {"self", "cls"}
            ]
            indices: set[tuple[int, str]] = set()
            for loop in (node for node in ast.walk(func.node) if isinstance(node, ast.For)):
                if not (
                    isinstance(loop.iter, ast.Call)
                    and _call_tail(loop.iter.func) == "range"
                    and loop.iter.args
                    and isinstance(loop.iter.args[0], ast.Name)
                    and loop.iter.args[0].id in params
                    and any(
                        _is_llm_call(call)
                        for call in ast.walk(loop)
                        if isinstance(call, ast.Call)
                    )
                ):
                    continue
                index = params.index(loop.iter.args[0].id)
                indices.add((index, loop.iter.args[0].id))
            # Keep every definition in the index, including helpers without
            # a budget sink.  That makes an unimported duplicate name
            # ambiguous instead of lending its sink to an unrelated call.
            sinks.setdefault(func.node.name, {}).setdefault(func.path, set()).update(indices)
        return sinks

    def _budget_findings(
        self, func: _Function, budget_sinks: dict[str, dict[Path, set[tuple[int, str]]]]
    ) -> list[Finding]:
        if not _is_route(func.node):
            return []
        containers: set[str] = set()
        # Framework route parameters are request-controlled even when the
        # handler uses injection rather than reading the global request object.
        tainted: set[str] = {
            arg.arg
            for arg in (*func.node.args.posonlyargs, *func.node.args.args)
            if arg.arg not in {"self", "cls", "request", "req"}
        }
        findings: list[Finding] = []
        for stmt in func.node.body:
            if (
                isinstance(stmt, (ast.Assign, ast.AnnAssign))
                and getattr(stmt, "value", None) is not None
            ):
                value = stmt.value
                names = _assigned_names(stmt)
                if any(
                    isinstance(call, ast.Call) and dotted_name(call.func).startswith("request.")
                    for call in ast.walk(value)
                ):
                    containers.update(names)
                elif (
                    isinstance(value, ast.Call)
                    and _call_tail(value.func) in {"min", "max"}
                    and any(
                        isinstance(arg, ast.Constant) and isinstance(arg.value, int)
                        for arg in value.args
                    )
                ):
                    # A fixed min/max bound is a real magnitude constraint;
                    # casting alone deliberately is not.
                    tainted.difference_update(names)
                elif _request_expr(value, containers, tainted):
                    tainted.update(names)
            for call in (node for node in ast.walk(stmt) if isinstance(node, ast.Call)):
                candidates = budget_sinks.get(_call_tail(call.func), {})
                positions: set[tuple[int, str]] = set()
                if len(candidates) == 1:
                    positions = next(iter(candidates.values()))
                elif candidates:
                    imported_module = self._imported_module(
                        func.module, _call_tail(call.func)
                    )
                    if imported_module:
                        for candidate_path, candidate_positions in candidates.items():
                            if candidate_path.stem == imported_module:
                                positions.update(candidate_positions)
                if any(
                    (
                        index < len(call.args)
                        and _request_expr(call.args[index], containers, tainted)
                    )
                    or any(
                        kw.arg == param and _request_expr(kw.value, containers, tainted)
                        for kw in call.keywords
                    )
                    for index, param in positions
                ):
                    findings.append(
                        Finding(
                            rule_id="AGENT-UNBOUNDED-BUDGET-001",
                            message=(
                                "Request-controlled agent iteration budget reaches a loop that performs LLM calls, "
                                "creating unbounded consumption (denial of wallet). "
                                "Clamp the budget to a fixed server-side maximum before invoking the agent."
                            ),
                            severity=Severity.HIGH,
                            category=Category.AI_ML,
                            file_path=str(func.path),
                            start_line=call.lineno,
                            confidence=0.9,
                            cwe_ids=[400],
                            engine=self.name,
                            metadata={
                                "budget_sink": _call_tail(call.func),
                                "structural_evidence": True,
                            },
                        )
                    )
        return findings

    @staticmethod
    def _imported_module(tree: ast.Module, local_name: str) -> str | None:
        """Resolve a simple ``from module import name`` ambiguity by basename."""
        for node in tree.body:
            if not isinstance(node, ast.ImportFrom) or not node.module:
                continue
            for alias in node.names:
                if alias.name == local_name and (alias.asname or alias.name) == local_name:
                    return node.module.rsplit(".", 1)[-1]
        return None

    @staticmethod
    def _markdown_findings(func: _Function) -> list[Finding]:
        if not (_MARKDOWN_NAME_RE.search(func.node.name) or _imports_markdown(func.module)):
            return []
        source = ast.unparse(func.node)
        if _SAFE_IMAGE_RE.search(source):
            return []
        findings: list[Finding] = []
        for call in (node for node in ast.walk(func.node) if isinstance(node, ast.Call)):
            if _call_tail(call.func) != "sub" or not call.args:
                continue
            templates = [
                arg.value
                for arg in call.args
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str)
            ]
            if not any(_IMAGE_TEMPLATE_RE.search(template) for template in templates):
                continue
            findings.append(
                Finding(
                    rule_id="MARKDOWN-IMAGE-EGRESS-001",
                    message=(
                        "Custom Markdown renderer emits image sources verbatim with no visible host allow-list. "
                        "Off-origin Markdown images can trigger zero-click browser egress when untrusted content is rendered."
                    ),
                    severity=Severity.HIGH,
                    category=Category.AI_ML,
                    file_path=str(func.path),
                    start_line=call.lineno,
                    confidence=0.85,
                    cwe_ids=[200],
                    engine="agent-flow",
                    metadata={"structural_evidence": True},
                )
            )
        input_names = {
            arg.arg
            for arg in (
                *func.node.args.posonlyargs,
                *func.node.args.args,
                *func.node.args.kwonlyargs,
            )
        }
        derived_names = set(input_names)
        changed = True
        while changed:
            changed = False
            for assignment in (
                node
                for node in ast.walk(func.node)
                if isinstance(node, (ast.Assign, ast.AnnAssign))
                and getattr(node, "value", None) is not None
            ):
                if not any(
                    isinstance(name, ast.Name) and name.id in derived_names
                    for name in ast.walk(assignment.value)
                ):
                    continue
                new_names = _assigned_names(assignment) - derived_names
                if new_names:
                    derived_names.update(new_names)
                    changed = True
        for returned in (
            node
            for node in ast.walk(func.node)
            if isinstance(node, ast.Return)
            and node.value is not None
            and isinstance(node.value, (ast.BinOp, ast.JoinedStr))
        ):
            text = ast.unparse(returned.value)
            if (
                "<img" in text
                and "src=" in text
                and any(
                    isinstance(name, ast.Name) and name.id in derived_names
                    for name in ast.walk(returned.value)
                )
            ):
                findings.append(
                    Finding(
                        rule_id="MARKDOWN-IMAGE-EGRESS-001",
                        message=(
                            "Custom Markdown renderer emits an image source from its input with no visible host allow-list. "
                            "Off-origin Markdown images can trigger zero-click browser egress when untrusted content is rendered."
                        ),
                        severity=Severity.HIGH,
                        category=Category.AI_ML,
                        file_path=str(func.path),
                        start_line=returned.lineno,
                        confidence=0.85,
                        cwe_ids=[200],
                        engine="agent-flow",
                        metadata={"structural_evidence": True},
                    )
                )
        return findings

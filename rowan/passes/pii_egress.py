"""Interprocedural PII-to-LLM egress analysis (LF-6 / V38)."""

from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass

from rowan.analysis.request_sources import dotted_name
from rowan.analysis.summary_fixpoint import solve_summaries
from rowan.core.confidence import CROSSFILE_TAINT
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.llm_sources import LLM_RECEIVER_CALL_RE
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.cross_file import (
    _extract_imports,
    _ImportGraph,
    _resolve_call_target,
    _resolve_callee_file,
)
from rowan.passes.sources import iter_python_sources

_RULE_ID = "TNT-ML-PII-EGRESS-001"
_PII_FIELDS = frozenset({
    "email", "ssn", "social_security_number", "dob", "date_of_birth",
    "phone", "phone_number", "address", "salary", "diagnosis",
    "medical_condition", "credit_card", "card_number", "passport_number",
})
_SANITIZER_RE = re.compile(
    r"(?:redact|anonymi[sz]e|mask|pseudonym|scrub|hash|tokeni[sz]e)", re.I
)
_LOCAL_HOST_RE = re.compile(
    r"(?:localhost|127\.0\.0\.1|0\.0\.0\.0|::1|host\.docker\.internal|\.internal\b|\.local\b)",
    re.I,
)
_PII = -1


@dataclass(frozen=True)
class _Summary:
    params: tuple[str, ...]
    return_origins: frozenset[int] = frozenset()
    sink_origins: frozenset[int] = frozenset()
    returns_pii: bool = False
    pii_to_sink: bool = False
    evidence_line: int = 0
    sink_line: int = 0


def _params(func: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    args = func.args
    return tuple(a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs))


def _is_pii_node(node: ast.AST) -> bool:
    if isinstance(node, ast.Attribute):
        return node.attr.lower() in _PII_FIELDS
    return (
        isinstance(node, ast.Subscript)
        and isinstance(node.slice, ast.Constant)
        and isinstance(node.slice.value, str)
        and node.slice.value.lower() in _PII_FIELDS
    )


def _is_sanitizer(call: ast.Call) -> bool:
    name = dotted_name(call.func)
    return bool(_SANITIZER_RE.search(name)) or name.endswith(".sub")


def _denies(body: list[ast.stmt]) -> bool:
    return bool(body) and isinstance(body[-1], (ast.Return, ast.Raise))


def _has_consent_gate(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for node in ast.walk(func):
        if not isinstance(node, ast.If) or not _denies(node.body):
            continue
        text = ast.unparse(node.test).lower()
        if "consent" in text and (text.startswith("not ") or " is false" in text):
            return True
    return False


def _literal_local_clients(func: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    local: set[str] = set()
    for node in ast.walk(func):
        if not (
            isinstance(node, ast.Assign)
            and len(node.targets) == 1
            and isinstance(node.targets[0], ast.Name)
            and isinstance(node.value, ast.Call)
        ):
            continue
        for kw in node.value.keywords:
            if kw.arg not in {"base_url", "api_base"}:
                continue
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                if _LOCAL_HOST_RE.search(kw.value.value):
                    local.add(node.targets[0].id)
    return local


def _is_direct_llm_sink(
    call: ast.Call,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    local_clients: set[str],
) -> bool:
    name = dotted_name(call.func)
    low = name.lower()
    receiver = name.split(".", 1)[0]
    if receiver in local_clients:
        return False
    if low in {"litellm.completion", "litellm.acompletion", "openai.chatcompletion.create"}:
        return True
    if any(
        part in low
        for part in (
            "chat.completions.create", "chat.completions.parse", "embeddings.create",
            "messages.create", "messages.stream", "responses.create", "generate_content",
        )
    ):
        return True
    # The shared LLM-call recogniser (CN-05): `llm.invoke`, `agent.run`, ...
    if LLM_RECEIVER_CALL_RE.search(name):
        return True
    if low in {"requests.post", "httpx.post", "aiohttp.post"} and re.search(
        r"(?:llm|chat|complet|embed)", func.name, re.I
    ):
        if call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str):
            return not bool(_LOCAL_HOST_RE.search(call.args[0].value))
        return True
    return False


def _call_key(
    call: ast.Call, file: str, imports: _ImportGraph, functions: dict[tuple[str, str], ast.AST]
) -> tuple[str, str] | None:
    name, qualifier = _resolve_call_target(call)
    if not name:
        return None
    target = _resolve_callee_file(file, name, qualifier, imports)
    key = (target, name) if target is not None else None
    return key if key in functions else None


def _bound_call_origins(
    call: ast.Call,
    callee: _Summary,
    expr_origins,
    selected: frozenset[int],
) -> set[int]:
    out: set[int] = set()
    for index in selected:
        if index < len(call.args):
            out |= expr_origins(call.args[index])
            continue
        if index >= len(callee.params):
            continue
        name = callee.params[index]
        out |= set().union(*(
            expr_origins(kw.value) for kw in call.keywords if kw.arg == name
        ), set())
    return out


def _analyze(
    file: str,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    functions: dict[tuple[str, str], ast.AST],
    imports: _ImportGraph,
    summaries: dict[tuple[str, str], _Summary],
) -> _Summary:
    params = _params(func)
    env: dict[str, set[int]] = {name: {i} for i, name in enumerate(params)}
    local_clients = _literal_local_clients(func)
    return_origins: set[int] = set()
    sink_origins: set[int] = set()
    pii_to_sink = False
    evidence_line = 0
    sink_line = 0

    def origins(expr: ast.AST) -> set[int]:
        if _is_pii_node(expr):
            return {_PII}
        if isinstance(expr, ast.Name):
            return set(env.get(expr.id, ()))
        if isinstance(expr, ast.Call):
            if _is_sanitizer(expr):
                return set()
            key = _call_key(expr, file, imports, functions)
            if key is not None and key in summaries:
                summary = summaries[key]
                out = _bound_call_origins(expr, summary, origins, summary.return_origins)
                if summary.returns_pii:
                    out.add(_PII)
                return out
        out: set[int] = set()
        for child in ast.iter_child_nodes(expr):
            out |= origins(child)
        return out

    consent = _has_consent_gate(func)
    for stmt in func.body:
        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            iter_origins = origins(stmt.iter)
            for target in ast.walk(stmt.target):
                if isinstance(target, ast.Name):
                    env[target.id] = set(iter_origins)
        for node in ast.walk(stmt):
            if _is_pii_node(node) and not evidence_line:
                evidence_line = getattr(node, "lineno", func.lineno)
        if isinstance(stmt, (ast.Assign, ast.AnnAssign)):
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            value_origins = origins(stmt.value) if stmt.value is not None else set()
            for target in targets:
                if isinstance(target, ast.Name):
                    env[target.id] = value_origins

        for call in (node for node in ast.walk(stmt) if isinstance(node, ast.Call)):
            call_origins = set().union(
                *(origins(arg) for arg in call.args),
                *(origins(kw.value) for kw in call.keywords),
                set(),
            )
            if _PII in call_origins and not evidence_line:
                evidence_line = call.lineno
            if isinstance(call.func, ast.Attribute) and call.func.attr in {"append", "extend", "update", "add"}:
                if isinstance(call.func.value, ast.Name):
                    env.setdefault(call.func.value.id, set()).update(call_origins)
            if _is_direct_llm_sink(call, func, local_clients):
                sink_origins |= {x for x in call_origins if x >= 0}
                if _PII in call_origins and not consent:
                    pii_to_sink = True
                    sink_line = call.lineno
            key = _call_key(call, file, imports, functions)
            if key is None or key not in summaries:
                continue
            callee = summaries[key]
            flowed = _bound_call_origins(call, callee, origins, callee.sink_origins)
            sink_origins |= {x for x in flowed if x >= 0}
            if _PII in flowed and callee.sink_origins and not consent:
                pii_to_sink = True
                sink_line = call.lineno
            if callee.pii_to_sink and _PII in call_origins and not consent:
                pii_to_sink = True
                sink_line = call.lineno

        if isinstance(stmt, ast.Return) and stmt.value is not None:
            return_origins |= origins(stmt.value)

    returns_pii = _PII in return_origins
    return_origins.discard(_PII)
    return _Summary(
        params=params,
        return_origins=frozenset(return_origins),
        sink_origins=frozenset(sink_origins),
        returns_pii=returns_pii,
        pii_to_sink=pii_to_sink,
        evidence_line=evidence_line,
        sink_line=sink_line,
    )


class PiiEgressPass:
    name = "pii_egress"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        parsed: list[tuple[str, ast.AST]] = []
        imports = _ImportGraph()
        functions: dict[tuple[str, str], ast.AST] = {}
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            file = str(path.resolve())
            parsed.append((file, tree))
            graph = _extract_imports(file, tree)
            imports.name_to_def.update(graph.name_to_def)
            imports.module_to_file.update(graph.module_to_file)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.setdefault((file, node.name), node)

        summaries = solve_summaries(
            functions,
            {key: _Summary(params=_params(node)) for key, node in functions.items()},
            lambda call, key: _call_key(call, key[0], imports, functions),
            lambda key, current: _analyze(key[0], functions[key], functions, imports, current),
        )

        for (file, name), summary in summaries.items():
            if not summary.pii_to_sink or not summary.evidence_line:
                continue
            result.add_finding(Finding(
                rule_id=_RULE_ID,
                message=(
                    f"PII read in '{name}' reaches an external LLM request through "
                    "interprocedural prompt/context propagation without visible "
                    "redaction, consent, or a local-only destination proof."
                ),
                severity=Severity.HIGH,
                category=Category.AI_ML,
                file_path=file,
                start_line=summary.evidence_line,
                confidence=CROSSFILE_TAINT(2),
                cwe_ids=[359],
                owasp_ids=["LLM02:2025"],
                engine="pii_egress",
                metadata={"source_function": name, "sink_line": summary.sink_line},
            ))
        result.files_scanned = len(parsed)
        scan_span(self.name, time.perf_counter() - start)
        return result

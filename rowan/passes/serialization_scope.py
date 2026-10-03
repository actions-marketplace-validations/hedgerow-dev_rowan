"""Serialization scope-widening detection pass.

Finds a class whose ``__init__`` accepts a security-scoping parameter that its
own serializer silently drops. Reload the serialized form and the constraint is
gone, so a round trip through config quietly widens what the object is allowed
to do.

AutoGen is the motivating case. ``FileSurfer.__init__`` takes ``base_path``,
the agent's only directory confinement, and ``_to_config()`` emits name,
model_client and description. ``TextMentionTermination.__init__`` takes
``sources``, which scopes which agents can end a run, and ``_to_config()`` emits
only ``text``. Both survive in memory and vanish on reload.

The check is deliberately narrow. A parameter counts only if its name starts a
word matching a scoping concept, and a serializer that walks attributes
reflectively is skipped because it drops nothing. Measured at 3 findings across
83,821 Python files.
"""

from __future__ import annotations

import ast
import logging
import time
from pathlib import Path

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

_RULE_ID = "SER-SCOPE-001"
_REMEDIATION = (
    "Add the parameter to the config model and emit it from the serializer, or "
    "raise from the serializer rather than returning a config that silently "
    "drops it."
)

#: Parameter-name concepts that constrain what an object may do. Matched at a
#: word start, never as a bare substring: `resources` must not match `sources`.
_SCOPING_MARKERS: tuple[str, ...] = (
    "base_path", "base_dir", "root_dir", "root_path",
    "allowed", "allowlist", "whitelist", "permitted",
    "sources", "permission", "scope", "role",
    "verify", "validate", "restrict", "sandbox",
    "read_only", "readonly", "trusted", "require",
)

#: Method names that serialize an instance back to a config or dict.
_SERIALIZER_NAMES: tuple[str, ...] = ("_to_config", "to_config", "to_dict")

#: Names whose presence means the serializer enumerates attributes generically,
#: so it cannot omit any single one.
_REFLECTIVE_NAMES: frozenset[str] = frozenset({
    "openapi_types", "attribute_map", "__dict__", "asdict", "model_dump", "vars",
})

_FuncDef = ast.FunctionDef | ast.AsyncFunctionDef


def _starts_word(name: str, marker: str) -> bool:
    """True if `marker` begins a word in `name` (start of string or after `_`)."""
    index = name.find(marker)
    while index != -1:
        if index == 0 or name[index - 1] == "_":
            return True
        index = name.find(marker, index + 1)
    return False


def _scoping_parameters(init: _FuncDef) -> list[str]:
    args = init.args
    found: list[str] = []
    for arg in [*args.posonlyargs, *args.args, *args.kwonlyargs]:
        if arg.arg == "self":
            continue
        lowered = arg.arg.lower()
        if any(_starts_word(lowered, marker) for marker in _SCOPING_MARKERS):
            found.append(arg.arg)
    return found


def _is_reflective(serializer: _FuncDef) -> bool:
    """True if the serializer walks attributes generically instead of naming them.

    Generated OpenAPI models iterate `self.openapi_types` and emit everything,
    so no parameter is dropped. Without this guard they were 26 of 29 findings.
    """
    for node in ast.walk(serializer):
        if isinstance(node, (ast.For, ast.AsyncFor, ast.DictComp, ast.ListComp)):
            return True
        if isinstance(node, ast.Attribute) and node.attr in _REFLECTIVE_NAMES:
            return True
        if isinstance(node, ast.Name) and node.id in _REFLECTIVE_NAMES:
            return True
    return False


def _referenced_names(serializer: _FuncDef) -> set[str]:
    """Every identifier and string literal the serializer mentions.

    A constructor parameter rarely keeps its name as an attribute (`sources`
    becomes `self._sources`, `text` becomes `self._termination_text`), so the
    caller substring-matches against this set rather than comparing exactly.
    """
    names: set[str] = set()
    for node in ast.walk(serializer):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
        elif isinstance(node, ast.Constant) and isinstance(node.value, str):
            names.add(node.value)
    return names


class SerializationScopePass:
    name = "serialization-scope"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        scanned = 0
        for py_file, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            scanned += 1
            result.findings.extend(self._scan_tree(py_file, tree))

        result.files_scanned = scanned
        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "SerializationScopePass: %d finding(s) in %.2fs", len(result.findings), duration
        )
        return result

    def _scan_tree(self, py_file: Path, tree: ast.AST) -> list[Finding]:
        findings: list[Finding] = []
        for cls in [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]:
            methods = {
                m.name: m for m in cls.body if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            init = methods.get("__init__")
            serializer = next(
                (methods[name] for name in _SERIALIZER_NAMES if name in methods), None
            )
            if init is None or serializer is None:
                continue
            if _is_reflective(serializer):
                continue

            emitted = _referenced_names(serializer)
            for param in _scoping_parameters(init):
                if any(param in name for name in emitted):
                    continue
                findings.append(Finding(
                    rule_id=_RULE_ID,
                    message=(
                        f"'{cls.name}.__init__' accepts '{param}', which constrains what "
                        f"the object may do, but '{serializer.name}()' does not emit it. "
                        f"Serializing and reloading this object drops the constraint, so "
                        f"the reloaded instance is more permissive than the original."
                    ),
                    severity=Severity.MEDIUM,
                    category=Category.CONFIG,
                    file_path=str(py_file),
                    start_line=serializer.lineno,
                    end_line=getattr(serializer, "end_lineno", serializer.lineno),
                    start_column=serializer.col_offset,
                    confidence=0.6,
                    cwe_ids=[1188],
                    engine="serialization-scope",
                    metadata={
                        "class_name": cls.name,
                        "dropped_parameter": param,
                        "serializer": serializer.name,
                        "remediation": _REMEDIATION,
                    },
                ))
        return findings

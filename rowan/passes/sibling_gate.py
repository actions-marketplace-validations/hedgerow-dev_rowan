"""SIBLING-001: a dangerous primitive used where the repo's own wrapper is skipped.

Most rules ask "is this call dangerous?", which needs world knowledge and is
why a generic `requests.get(url)` rule drowns in false positives. This pass
asks a different question, one the codebase answers for itself:

    This repo defines a validated wrapper around a dangerous primitive, and
    uses it in N places. Here is the one place that calls the primitive
    directly instead.

The invariant comes from the code under analysis, not from us, so the finding
carries evidence on both sides: the wrapper that exists, and the sibling call
sites that honour it. That is a far stronger claim than "unvalidated fetch",
and it is one an LLM reviewer structurally struggles to make -- it requires
enumerating every call site in the repository, not reasoning locally.

Validated against the NVIDIA Dynamo assessment (2026-08-06), where multi-
backend drift produced exactly this shape: five SSRF CVEs were fixed, one
backend kept its private unvalidated copy, and a sixth instance survived in
the Omni TTS handler.

Precision comes from four requirements, all of which must hold:

1. The wrapper must be a *thin* facade over the primitive (few statements),
   so we do not mistake a large business-logic function for a safety wrapper.
2. The wrapper must show validation intent: it guards, raises, or calls
   something whose name reads like a check.
3. The wrapper must be genuinely established: used by at least
   ``_MIN_SIBLING_USES`` distinct call sites.
4. The bypassing call must be in a different function from the wrapper
   itself (the wrapper calls the primitive by definition).
"""

from __future__ import annotations

import ast
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

from rowan.analysis.test_paths import is_test_path
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, scan_span
from rowan.passes.sources import iter_python_sources

logger = logging.getLogger(__name__)

#: Dangerous primitives worth wrapping, as (attribute chain suffix, category).
#: Deliberately short: each entry must be something a codebase plausibly
#: centralises behind a helper. A primitive nobody ever wraps produces no
#: wrapper and therefore no findings, which is the correct outcome.
_PRIMITIVES: dict[tuple[str, ...], Category] = {
    ("requests", "get"): Category.SSRF,
    ("requests", "post"): Category.SSRF,
    ("httpx", "get"): Category.SSRF,
    ("httpx", "post"): Category.SSRF,
    ("urlopen",): Category.SSRF,
    ("aiohttp", "request"): Category.SSRF,
    ("pickle", "load"): Category.DESERIALIZATION,
    ("pickle", "loads"): Category.DESERIALIZATION,
    ("torch", "load"): Category.DESERIALIZATION,
    ("yaml", "load"): Category.DESERIALIZATION,
    ("subprocess", "run"): Category.COMMAND_INJECTION,
    ("subprocess", "Popen"): Category.COMMAND_INJECTION,
    ("subprocess", "check_output"): Category.COMMAND_INJECTION,
    ("os", "system"): Category.COMMAND_INJECTION,
    ("shutil", "unpack_archive"): Category.PATH_TRAVERSAL,
}

#: A wrapper body longer than this is business logic that happens to make a
#: call, not a safety facade.
_MAX_WRAPPER_STATEMENTS = 25

#: Distinct call sites required before we treat a helper as the established
#: convention. Two is enough to establish a pattern while staying strict:
#: a helper used once is not yet a convention, and flagging against it would
#: be arguing with the author rather than reporting their own inconsistency.
_MIN_SIBLING_USES = 3

#: Distinct FILES that must use the wrapper. A helper called three times
#: inside its own module is local style; a convention worth holding other
#: code to is one the repo reaches for across module boundaries. This is
#: what separates `ssrf_safe_get` (imported widely) from `load_data`
#: (a method used beside its own definition).
_MIN_SIBLING_FILES = 2

#: Names that signal a function validates rather than merely delegates.
_VALIDATION_NAME_HINTS = (
    "valid", "check", "verify", "assert", "ensure", "sanitiz", "sanitis",
    "allow", "deny", "guard", "safe", "restrict", "permit", "authoriz",
    "authoris", "resolve", "normaliz", "normalis", "clean",
)


@dataclass
class _Wrapper:
    """A repo-defined function that fronts a dangerous primitive."""

    name: str
    file: str
    line: int
    primitive: str
    category: Category
    validation_evidence: str
    call_sites: list[tuple[str, int]] = field(default_factory=list)


def _attr_chain(node: ast.AST) -> tuple[str, ...]:
    parts: list[str] = []
    cur = node
    while isinstance(cur, ast.Attribute):
        parts.append(cur.attr)
        cur = cur.value
    if isinstance(cur, ast.Name):
        parts.append(cur.id)
    return tuple(reversed(parts))


def _matched_primitive(call: ast.Call) -> tuple[str, Category] | None:
    chain = _attr_chain(call.func)
    if not chain:
        return None
    for key, category in _PRIMITIVES.items():
        if len(chain) >= len(key) and tuple(chain[-len(key):]) == key:
            return ".".join(key), category
    return None


def _names_in(node: ast.AST) -> set[str]:
    return {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def _primitive_arg_names(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    """Parameter names that flow (directly or via one assignment) into the
    primitive call's arguments. A wrapper guards *the value it passes*; a
    function that validates something unrelated is not a facade."""
    params = {a.arg for a in fn.args.args} | {a.arg for a in fn.args.kwonlyargs}
    if fn.args.vararg:
        params.add(fn.args.vararg.arg)
    # `self`/`cls` are not what a caller hands in. Counting them made every
    # method that touches `self.anything` look like a facade: it is how
    # `check_installation(self)` -- which guards its own access token and
    # wraps nothing -- became a "wrapper" with 28 bypasses.
    params -= {"self", "cls"}
    # local = f(param) makes `local` a stand-in for `param`
    aliases: dict[str, set[str]] = {}
    for node in ast.walk(fn):
        if isinstance(node, ast.Assign) and node.value is not None:
            src = _names_in(node.value) & (params | set(aliases))
            if src:
                for tgt in node.targets:
                    for name in _names_in(tgt):
                        aliases.setdefault(name, set()).update(src)
    reaching: set[str] = set()
    for node in ast.walk(fn):
        if isinstance(node, ast.Call) and _matched_primitive(node):
            used = set()
            for arg in list(node.args) + [kw.value for kw in node.keywords if kw.value]:
                used |= _names_in(arg)
            for name in used:
                if name in params:
                    reaching.add(name)
                reaching |= aliases.get(name, set()) & params
    return reaching


def _validation_evidence(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> str | None:
    """Describe why this function guards the value it passes on, or None.

    The guard must reference the same parameter that reaches the primitive.
    Without that link every function containing a `raise` and an HTTP call
    looks like a safety wrapper: on one corpus repo that admitted
    `check_installation()` and `execute_code()`, producing 54 false
    findings out of 55.
    """
    guarded = _primitive_arg_names(fn)
    if not guarded:
        return None
    # Validation precedes the operation it protects; anything after the call
    # is error handling. Without this line, `response = requests.get(url)`
    # followed by `if response.status_code != 200: raise` reads as a guard on
    # `url`, which made every competent HTTP helper in the corpus look like a
    # security wrapper (llamaindex `get`, ragflow `make_request`).
    call_line = min(
        (n.lineno for n in ast.walk(fn)
         if isinstance(n, ast.Call) and _matched_primitive(n)),
        default=None,
    )
    if call_line is None:
        return None
    # A guard on a value DERIVED from the parameter still guards it:
    # `host = urlparse(url).hostname` then `if host not in ALLOWED: raise`
    # is a check on `url`. Without this the commonest wrapper shape of all
    # is missed.
    related = set(guarded)
    for _ in range(3):  # transitive closure, bounded (host = f(url), h2 = g(host))
        grew = False
        for node in ast.walk(fn):
            if isinstance(node, ast.Assign) and node.value is not None:
                if node.lineno >= call_line:
                    continue  # derived from the call's own result
                if any(_matched_primitive(c) for c in ast.walk(node.value)
                       if isinstance(c, ast.Call)):
                    continue
                if _names_in(node.value) & related:
                    for tgt in node.targets:
                        for name in _names_in(tgt):
                            if name not in related:
                                related.add(name)
                                grew = True
        if not grew:
            break
    guarded = related

    for node in ast.walk(fn):
        # `if <test mentioning the guarded value>: raise ...`
        if isinstance(node, ast.If) and node.lineno < call_line and _names_in(node.test) & guarded:
            if any(isinstance(s, (ast.Raise, ast.Return)) for s in ast.walk(node)):
                return f"rejects a bad {sorted(guarded)[0]} before using it"
        if isinstance(node, ast.Assert) and node.lineno < call_line and _names_in(node.test) & guarded:
            return f"asserts a precondition on {sorted(guarded)[0]}"
        if isinstance(node, ast.Call) and node.lineno < call_line:
            called = _attr_chain(node.func)
            if not called or not any(h in called[-1].lower() for h in _VALIDATION_NAME_HINTS):
                continue
            args = set()
            for arg in list(node.args) + [kw.value for kw in node.keywords if kw.value]:
                args |= _names_in(arg)
            if args & guarded:
                return f"passes {sorted(args & guarded)[0]} through {'.'.join(called)}()"
    return None


def _statement_count(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    return sum(1 for n in ast.walk(fn) if isinstance(n, ast.stmt))


def _enclosing_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _module_level_functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    """Only module-level functions are candidate wrappers.

    A shared safety convention is a utility other modules import, not a
    method name. Keying wrappers by bare name conflated same-named methods
    across unrelated classes: every llamaindex reader defines `load_data`
    and every ragflow connector a `load_credentials`, so one class's method
    became "the convention" and every other class's primitive call read as
    a bypass (72 and 34 findings respectively, all spurious).
    """
    return [n for n in getattr(tree, "body", [])
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _find_wrappers(trees: dict[str, ast.AST]) -> dict[str, _Wrapper]:
    """Find thin, validating functions that front a dangerous primitive."""
    wrappers: dict[str, _Wrapper] = {}
    for file_path, tree in trees.items():
        for fn in _module_level_functions(tree):
            # A dunder is a constructor or protocol hook, not a facade a
            # caller chooses over a primitive. `__init__` qualifying made
            # every instantiation in the repo look like a convention.
            if fn.name.startswith("__") and fn.name.endswith("__"):
                continue
            if _statement_count(fn) > _MAX_WRAPPER_STATEMENTS:
                continue
            primitive: tuple[str, Category] | None = None
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    primitive = _matched_primitive(node) or primitive
            if primitive is None:
                continue
            evidence = _validation_evidence(fn)
            if evidence is None:
                continue
            # A later definition of the same name does not replace an earlier
            # one: the first is as good a convention as any, and picking
            # deterministically keeps output stable across runs.
            wrappers.setdefault(fn.name, _Wrapper(
                name=fn.name, file=file_path, line=fn.lineno,
                primitive=primitive[0], category=primitive[1],
                validation_evidence=evidence,
            ))
    return wrappers


def _collect_call_sites(trees: dict[str, ast.AST], wrappers: dict[str, _Wrapper]) -> None:
    """Record where each wrapper is actually used.

    A call counts only when it is bound to the wrapper's definition: a bare
    `name(...)` defined in or imported from the wrapper's file, or
    `module.name(...)` with `module` bound to that file. Matching the last
    attribute alone counted every `dict.get()` as a use of a wrapper named
    `get` (XF-19).
    """
    from rowan.passes.cross_file import _extract_imports

    by_def = {(str(Path(w.file).resolve()), w.name): w for w in wrappers.values()}
    for file_path, tree in trees.items():
        here = str(Path(file_path).resolve())
        imports = _extract_imports(here, tree)
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            chain = _attr_chain(node.func)
            if len(chain) == 1:
                target = imports.name_to_def.get((here, chain[0]), (here, chain[0]))
            elif len(chain) == 2 and (here, chain[0]) in imports.module_to_file:
                target = (imports.module_to_file[(here, chain[0])], chain[1])
            else:
                continue
            wrapper = by_def.get(target)
            if wrapper is None:
                continue
            if file_path == wrapper.file and node.lineno == wrapper.line:
                continue
            wrapper.call_sites.append((file_path, node.lineno))


def _find_bypasses(
    trees: dict[str, ast.AST], wrappers: dict[str, _Wrapper]
) -> list[tuple[_Wrapper, str, int, str]]:
    """Direct primitive calls that skip an established wrapper."""
    by_primitive: dict[str, list[_Wrapper]] = {}
    for w in wrappers.values():
        distinct_files = {c[0] for c in w.call_sites}
        if len(distinct_files) >= _MIN_SIBLING_FILES and len(w.call_sites) >= _MIN_SIBLING_USES:
            by_primitive.setdefault(w.primitive, []).append(w)

    out: list[tuple[_Wrapper, str, int, str]] = []
    for file_path, tree in trees.items():
        for fn in _enclosing_functions(tree):
            for node in ast.walk(fn):
                if not isinstance(node, ast.Call):
                    continue
                matched = _matched_primitive(node)
                if matched is None:
                    continue
                candidates = by_primitive.get(matched[0])
                if not candidates:
                    continue
                # The wrapper itself calls the primitive; that is not a bypass.
                if any(fn.name == w.name for w in candidates):
                    continue
                # Neither is a second helper that is itself validated.
                if _validation_evidence(fn) is not None and _statement_count(fn) <= _MAX_WRAPPER_STATEMENTS:
                    continue
                out.append((candidates[0], file_path, node.lineno, fn.name))
    return out


class SiblingGatePass:
    """Flag a dangerous primitive used where the repo's own wrapper is skipped."""

    name = "sibling_gate"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()
        result = ScanResult()
        target = context.target_path
        if not target.exists():
            return result

        trees: dict[str, ast.AST] = {}
        for path, tree in iter_python_sources(context, owner=self.name, skip_tests=False):
            # Judge the path RELATIVE to the scan root. `is_test_path` on an
            # absolute path treats any repo living under a directory whose
            # name tokenises to "test"/"spec" as test code -- including
            # pytest's own tmp_path, which is named after the test function
            # (see issue #272).
            try:
                rel = str(path.resolve().relative_to(target.resolve()))
            except ValueError:
                rel = str(path)
            if is_test_path(rel):
                continue
            trees[str(path)] = tree

        wrappers = _find_wrappers(trees)
        if not wrappers:
            scan_span(self.name, time.perf_counter() - start)
            return result
        _collect_call_sites(trees, wrappers)

        for wrapper, file_path, line, fn_name in _find_bypasses(trees, wrappers):
            uses = len(wrapper.call_sites)
            rel_wrapper = Path(wrapper.file).name
            result.add_finding(Finding(
                rule_id="SIBLING-001",
                message=(
                    f"{fn_name}() calls {wrapper.primitive}() directly, bypassing "
                    f"{wrapper.name}() in {rel_wrapper}:{wrapper.line}, which this "
                    f"repository defines for exactly this purpose and uses at "
                    f"{uses} other call sites. That wrapper {wrapper.validation_evidence}; "
                    f"this call does not. The inconsistency is the finding: the codebase "
                    f"already knows the safe way to do this."
                ),
                severity=Severity.MEDIUM,
                category=wrapper.category,
                file_path=file_path,
                start_line=line,
                confidence=0.75,
                engine="siblinggate",
                metadata={
                    "sibling_gate": True,
                    "wrapper_name": wrapper.name,
                    "wrapper_file": wrapper.file,
                    "wrapper_line": wrapper.line,
                    "wrapper_evidence": wrapper.validation_evidence,
                    "primitive": wrapper.primitive,
                    "sibling_call_sites": [f"{Path(f).name}:{ln}" for f, ln in wrapper.call_sites[:10]],
                    "sibling_use_count": uses,
                },
            ))

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "SiblingGatePass: %d wrappers, %d bypasses in %.1fs",
            len(wrappers), len(result.findings), duration,
        )
        return result

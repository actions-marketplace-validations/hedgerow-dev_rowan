"""One discovery policy for every AST pass (BACKLOG CN-01).

Fifteen passes used to carry their own copy of: enumerate `*.py`, skip
hidden and vendored directories, skip tests, apply `.rowanignore`, guard
symlink escapes, parse. The copies drifted (absolute-path checks, missing
per-file `try`), and each drift was a silent zero for one pass. Passes now
iterate `iter_python_sources(context, ...)` and get the same files, the same
exclusions and the same failure handling: a file that cannot be read or
parsed is counted on the snapshot and skipped, never allowed to abort the
pass.
"""

from __future__ import annotations

import ast
import logging
from collections.abc import Collection, Iterable, Iterator
from pathlib import Path

from rowan.core.paths import is_within_root, iter_within_root
from rowan.passes.base import ScanContext
from rowan.passes.file_scan import (
    _parts_under,
    is_hidden_under,
    is_ignored,
    load_ignore_patterns,
)

logger = logging.getLogger(__name__)

#: Directories below the scan root that hold third-party code.
VENDORED_PARTS = frozenset({"site-packages", "dist-packages", "node_modules"})


def is_simple_test_path(rel_parts: tuple[str, ...], name: str) -> bool:
    """The test exclusion the AST passes agreed on: a `test`/`tests` path
    component or a `test_` file prefix. Narrower than
    `analysis.test_paths.is_test_path` on purpose; that one also drops
    examples and fixtures, which several passes want to see."""
    return any(part.lower() in ("test", "tests") for part in rel_parts) or name.startswith(
        "test_"
    )


def filter_python_paths(
    root: Path,
    candidates: Iterable[Path],
    ignores: list[str],
    *,
    skip_tests: bool,
    require_file: bool = True,
    excluded_parts: Collection[str] = VENDORED_PARTS,
) -> Iterator[Path]:
    """The one exclusion policy: symlink escapes, hidden and vendored
    directories below the root, optionally tests, and `.rowanignore`."""
    for path in candidates:
        if require_file and not path.is_file():
            continue
        # A symlinked file can point outside the scan root (CWE-59).
        if not is_within_root(path, root):
            continue
        rel_parts = _parts_under(path, root)
        if is_hidden_under(path, root):
            continue
        if any(part in excluded_parts for part in rel_parts):
            continue
        if skip_tests and is_simple_test_path(rel_parts, path.name):
            continue
        if ignores and is_ignored("/".join(rel_parts), ignores):
            continue
        yield path


def iter_python_files(
    context: ScanContext,
    *,
    skip_tests: bool,
    candidates: Iterable[Path] | None = None,
    excluded_parts: Collection[str] = VENDORED_PARTS,
) -> Iterator[Path]:
    """Python files under the scan root that a pass should look at."""
    root = context.target_path
    ignores = load_ignore_patterns(root, context.config)
    supplied_candidates = candidates is not None or context.source_inventory is not None
    if candidates is None:
        if context.source_inventory is not None:
            candidates = context.source_inventory.paths_for("python", suffix=".py")
        else:
            candidates = iter_within_root(root, "*.py")
    yield from filter_python_paths(
        root,
        candidates,
        ignores,
        skip_tests=skip_tests,
        require_file=not supplied_candidates,
        excluded_parts=excluded_parts,
    )


def iter_python_sources(
    context: ScanContext,
    *,
    owner: str,
    skip_tests: bool,
    candidates: Iterable[Path] | None = None,
    excluded_parts: Collection[str] = VENDORED_PARTS,
) -> Iterator[tuple[Path, ast.Module]]:
    """`(path, tree)` for every parseable Python file a pass should look at.

    Read and parse failures are already counted by the snapshot; anything
    else raised while producing one file's tree is recorded under
    `degraded_passes[owner]` and the file is skipped.
    """
    failures = 0
    for path in iter_python_files(
        context,
        skip_tests=skip_tests,
        candidates=candidates,
        excluded_parts=excluded_parts,
    ):
        try:
            tree = context.source_snapshot.python_ast(path)
        except Exception as exc:  # one file must not take down the pass
            failures += 1
            logger.warning("%s: skipping %s: %s", owner, path, exc)
            continue
        if tree is None:
            continue
        yield path, tree
    if failures:
        context.result.degraded_passes[owner] = f"{failures} file(s) skipped after an error"

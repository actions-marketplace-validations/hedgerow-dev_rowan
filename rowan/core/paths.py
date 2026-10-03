"""Shared path-confinement check for every file-discovery walk.

A scan target is untrusted input: nothing stops it from containing a symlink
that points outside the scan root. ``Path.rglob`` does not recurse into a
symlinked *directory*, but it does yield a symlink to a *file*, and
``Path.is_file()`` follows that symlink. Every walk that does not check the
resolved target against the root can be made to read (and, via SCA dependency
extraction, MCP config parsing, or LLM finding context, exfiltrate) arbitrary
files outside the scanned repository.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path


def is_within_root(path: Path, root: Path) -> bool:
    """True if ``path`` resolves to a location at or under ``root``.

    Use this before trusting a symlinked file discovered under a scan target:
    ``if path.is_symlink() and not is_within_root(path, root): skip it``.
    Also safe to call on a non-symlink path (it just confirms the obvious).
    """
    try:
        resolved = path.resolve()
        root_resolved = root.resolve()
    except OSError:
        return False
    return resolved == root_resolved or root_resolved in resolved.parents


def iter_within_root(root: Path, pattern: str) -> Iterator[Path]:
    """Yield paths matching ``pattern`` whose resolved location stays in ``root``.

    Discovery walks must use this instead of ``Path.rglob`` directly.  A
    symlinked file is yielded by ``rglob`` even though a symlinked directory is
    not traversed, so checking only callers that happen to call ``is_file`` is
    insufficient.
    """
    for path in root.rglob(pattern):
        if is_within_root(path, root):
            yield path


def repo_search_dirs(start: Path) -> list[Path]:
    """Directories to search for per-repository files (config, ignore list).

    From ``start`` upward to the first directory containing ``.git``,
    inclusive; just ``start`` when no ``.git`` is found. A file above the
    repository (``$HOME``, a parent monorepo folder) must not silently change
    a scan's results (PL-11).
    """
    start = start.resolve()
    chain = [start, *start.parents]
    for index, directory in enumerate(chain):
        if (directory / ".git").exists():
            return chain[: index + 1]
    return [start]

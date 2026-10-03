"""Pipeline base types: shared state and pass protocol."""

from __future__ import annotations

import ast
import pickle
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.core.rules import NeuroScanRule


@dataclass(frozen=True)
class SourceFile:
    """One source-like file admitted to the resolved scan scope."""

    path: Path
    languages: frozenset[str]


@dataclass(frozen=True)
class SourceInventory:
    """Scan-owned, immutable inventory published by the discovery pass.

    ``None`` on :class:`ScanContext` means discovery has not run, which lets
    individual passes retain their standalone repository-walk behavior.  An
    empty inventory is different: discovery ran and the resolved scope has no
    applicable source files, so consumers must not widen it with a fallback
    walk.
    """

    files: tuple[SourceFile, ...] = ()
    dependency_manifests: tuple[Path, ...] = ()
    model_artifacts: tuple[Path, ...] = ()
    mcp_config_files: tuple[Path, ...] = ()

    def paths_for(self, language: str, *, suffix: str | None = None) -> tuple[Path, ...]:
        """Return paths classified for ``language``, optionally by exact suffix."""

        return tuple(
            source.path
            for source in self.files
            if language in source.languages
            and (suffix is None or source.path.suffix == suffix)
        )


class SourceSnapshot:
    """Lazy, bounded source-text and Python-syntax cache for one scan.

    Read and parse failures are cached as ``None`` so every migrated pass sees
    the same per-scan result and does not repeatedly retry a broken file. ASTs
    are returned as private copies unpickled from the cached tree, so one
    analyzer cannot mutate a tree in a way that leaks into another.

    The independent LRU bounds keep a large scan from retaining every source
    and syntax tree indefinitely. Eviction can cause a later pass to repeat
    work, but never changes the result contract.
    """

    def __init__(self, max_entries: int = 2048):
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        self._max_entries = max_entries
        self._text: OrderedDict[Path, str | None] = OrderedDict()
        self._python: OrderedDict[Path, bytes | None] = OrderedDict()
        self._text_hits = 0
        self._text_misses = 0
        self._python_hits = 0
        self._python_misses = 0
        self._read_failures = 0
        self._parse_failures = 0
        # Distinct files, so a re-parse after cache eviction is not a second
        # failure, and the scan can name them (PL-09).
        self._parse_failed: set[Path] = set()
        self._lock = threading.RLock()

    def _store(self, cache, path: Path, value) -> None:
        cache[path] = value
        cache.move_to_end(path)
        while len(cache) > self._max_entries:
            cache.popitem(last=False)

    def read_text(self, path: Path) -> str | None:
        """Read UTF-8 source once per retained entry, caching I/O failure."""

        with self._lock:
            if path in self._text:
                self._text_hits += 1
                self._text.move_to_end(path)
                return self._text[path]
            self._text_misses += 1
            try:
                source = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                source = None
                self._read_failures += 1
            self._store(self._text, path, source)
            return source

    def python_ast(self, path: Path) -> ast.Module | None:
        """Return an isolated copy of the cached Python AST, or cached failure."""

        with self._lock:
            if path not in self._python:
                self._python_misses += 1
                source = self.read_text(path)
                try:
                    tree = ast.parse(source, filename=str(path)) if source is not None else None
                    # Cache the tree pickled: unpickling a private copy for each
                    # caller is several times faster than copy.deepcopy on large
                    # repositories. The bytes come from our own parse and never
                    # leave this process.
                    blob = pickle.dumps(tree, pickle.HIGHEST_PROTOCOL) if tree is not None else None
                except (SyntaxError, ValueError, RecursionError, MemoryError):
                    # A pathological file ("parser stack overflowed" on a long
                    # unary chain) is a parse failure like any other, not a
                    # reason for the calling pass to abort.
                    blob = None
                    if path not in self._parse_failed:
                        self._parse_failed.add(path)
                        self._parse_failures += 1
                self._store(self._python, path, blob)
            else:
                self._python_hits += 1
                self._python.move_to_end(path)
            blob = self._python[path]
        return pickle.loads(blob) if blob is not None else None  # noqa: S301

    def parse_failed_paths(self) -> list[Path]:
        with self._lock:
            return sorted(self._parse_failed)

    def stats(self) -> dict[str, int]:
        """Return path-free scan-lifetime cache and failure telemetry."""

        with self._lock:
            return {
                "text_entries": len(self._text),
                "python_ast_entries": len(self._python),
                "text_hits": self._text_hits,
                "text_misses": self._text_misses,
                "python_ast_hits": self._python_hits,
                "python_ast_misses": self._python_misses,
                "read_failures": self._read_failures,
                "parse_failures": self._parse_failures,
            }


@dataclass
class ScanContext:
    target_path: Path
    config: ScanConfig
    result: ScanResult
    neuroscan_rules: list[NeuroScanRule] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    source_inventory: SourceInventory | None = None
    source_snapshot: SourceSnapshot = field(default_factory=SourceSnapshot)
    # A scan-owned budget for I/O that leaves the process.  Passes may run in
    # parallel, and individual passes may use their own worker pools, so a
    # local pool limit is not sufficient to bound network fan-out.
    network_semaphore: threading.BoundedSemaphore = field(
        default_factory=lambda: threading.BoundedSemaphore(1)
    )


class PipelineStep(Protocol):
    name: str

    def run(self, context: ScanContext) -> ScanResult: ...


def scan_span(name: str, duration: float) -> None:
    """Emit a timing span for observability."""
    import logging

    logger = logging.getLogger("rowan")
    logger.info("Span[%s] %.2fs", name, duration)

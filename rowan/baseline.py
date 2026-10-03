"""Baseline / diff mode.

Fingerprints findings so a scan can report (and a CI run can gate on) only
*new* findings relative to a committed baseline. Fingerprints are content-
addressed (based on the rule id, the file's path relative to the scan root,
and the stripped source at the finding line), so findings that merely shift to
a different line number do not churn the baseline.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from pathlib import Path

from rowan.core.findings import Finding, ScanResult

BASELINE_VERSION = 1


def _relpath(file_path: str, root: Path) -> str:
    try:
        return str(Path(file_path).resolve().relative_to(root.resolve()))
    except (ValueError, OSError):
        return file_path


# Keep a cache only while the on-disk identity is unchanged. Rowan is
# also used as a long-lived library/MCP process, so a path alone is never a
# valid cache key: a later scan may edit, delete, or recreate it.
_LINE_CACHE_MAX = 256
_line_cache: OrderedDict[str, tuple[tuple[int, int, int, int] | None, list[str]]] = OrderedDict()


def _file_identity(path: Path) -> tuple[int, int, int, int] | None:
    try:
        stat = path.stat()
    except OSError:
        return None
    return (stat.st_dev, stat.st_ino, stat.st_mtime_ns, stat.st_size)


def _code_at(file_path: str, line: int) -> str:
    """Return the stripped source at a 1-indexed line, or '' if unavailable."""
    if not file_path or line <= 0:
        return ""
    path = Path(file_path)
    identity = _file_identity(path)
    cached = _line_cache.get(file_path)
    if cached is None or cached[0] != identity:
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            lines = []
        _line_cache[file_path] = (identity, lines)
        _line_cache.move_to_end(file_path)
        while len(_line_cache) > _LINE_CACHE_MAX:
            _line_cache.popitem(last=False)
    else:
        _line_cache.move_to_end(file_path)
        lines = cached[1]
    if 0 < line <= len(lines):
        return lines[line - 1].strip()
    return ""


def fingerprint(finding: Finding, root: Path) -> str:
    """Stable, content-addressed fingerprint for a finding."""
    rel = _relpath(finding.file_path, root)
    code = _code_at(finding.file_path, finding.start_line)
    # Fall back to the message when there is no resolvable code line (e.g. SCA
    # findings that point at a manifest rather than a specific line of code).
    basis = "|".join([finding.rule_id, rel, code or finding.message.strip()])
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def write_baseline(
    result: ScanResult,
    path: Path,
    root: Path,
    view: str | None = None,
    severity: str | None = None,
) -> int:
    """Write the fingerprints of all current findings to ``path``.

    `view` and `severity` record the run's report filters for diagnosis only;
    the fingerprints always cover the unfiltered result.
    """
    fps = sorted({fingerprint(f, root) for f in result.findings})
    payload = {"version": BASELINE_VERSION, "fingerprints": fps, "view": view, "severity": severity}
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return len(fps)


def load_baseline(path: Path) -> set[str]:
    """Load the set of baseline fingerprints from ``path``."""
    data = json.loads(path.read_text(encoding="utf-8"))
    return set(data.get("fingerprints", []))


def filter_new(result: ScanResult, baseline: set[str], root: Path) -> int:
    """Drop findings present in the baseline in place; return the count dropped."""
    kept: list[Finding] = []
    suppressed = 0
    for f in result.findings:
        if fingerprint(f, root) in baseline:
            suppressed += 1
        else:
            kept.append(f)
    result.findings = kept
    return suppressed

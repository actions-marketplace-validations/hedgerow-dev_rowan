"""Stable root-cause clustering for report presentation.

The scanner's raw findings remain the source of truth.  This module derives a
second, lossless review dimension for propagated taint findings that terminate
at the same concrete sink.  Authorization and other non-flow findings are
always singletons: sharing a line or rule is not evidence that two policy
boundaries have the same root cause.
"""

from __future__ import annotations

import hashlib
import json
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from rowan.core.findings import Finding

_CALL_SYMBOL_RE = re.compile(
    r"(?<![\w$])((?:[A-Za-z_$][\w$]*\.)*[A-Za-z_$][\w$]*)\s*\("
)
_NON_CALL_WORDS = frozenset({"if", "for", "while", "return", "with", "switch"})


@dataclass(frozen=True)
class FindingCluster:
    """One review root with indexes into the unchanged raw finding list."""

    cluster_id: str
    sink_file: str
    sink_line: int
    sink_rule: str
    sink_symbol: str
    member_indexes: tuple[int, ...]
    primary_index: int


def concrete_sink_symbol(snippet: str) -> str:
    """Return one concrete call symbol, or empty when the snippet is ambiguous."""
    symbols = [
        match.group(1)
        for match in _CALL_SYMBOL_RE.finditer(snippet or "")
        if match.group(1) not in _NON_CALL_WORDS
    ]
    return symbols[0] if len(symbols) == 1 else ""


def _normalized_path(path: str, source_root: str) -> str:
    candidate = Path(path)
    if source_root:
        with suppress(OSError, ValueError):
            candidate = candidate.resolve().relative_to(Path(source_root).resolve())
    return candidate.as_posix()


def _digest(parts: tuple[object, ...]) -> str:
    encoded = json.dumps(parts, separators=(",", ":"), ensure_ascii=True).encode()
    return "orc-" + hashlib.sha256(encoded).hexdigest()[:20]


def _root_identity(
    finding: Finding, source_root: str
) -> tuple[str, int, str, str] | None:
    """Return a proven propagated sink identity, never a guessed policy root."""
    metadata = finding.metadata or {}
    flow = finding.taint_flow
    if not (
        flow
        and flow.sink
        and (finding.engine == "crossfile" or metadata.get("cross_file"))
    ):
        return None

    sink_symbol = str(metadata.get("sink_symbol") or "")
    if not sink_symbol:
        sink_symbol = concrete_sink_symbol(flow.sink.snippet)
    sink_rule = str(metadata.get("sink_rule_id") or "")
    # Without both pieces of concrete terminal identity, merging would risk
    # collapsing distinct calls or boundaries that happen to share a line.
    if not sink_symbol or not sink_rule:
        return None
    return (
        _normalized_path(flow.sink.file_path, source_root),
        flow.sink.line,
        sink_rule,
        sink_symbol,
    )


def _primary_index(indexes: list[int], findings: list[Finding]) -> int:
    """Prefer the shortest, strongest trace while keeping ordering stable."""
    return min(
        indexes,
        key=lambda idx: (
            int((findings[idx].metadata or {}).get("hop_depth", 1_000_000)),
            findings[idx].severity_order,
            -findings[idx].confidence,
            findings[idx].file_path,
            findings[idx].start_line,
            str((findings[idx].metadata or {}).get("caller") or ""),
            idx,
        ),
    )


def cluster_findings(
    findings: list[Finding], source_root: str = ""
) -> list[FindingCluster]:
    """Derive lossless review clusters from ``findings``.

    Only propagated findings with a concrete terminal tuple are coalesced.
    Every other finding becomes a singleton cluster, preserving authorization
    boundaries and uncertain sink identities.
    """
    grouped: dict[tuple[str, int, str, str], list[int]] = {}
    singletons: list[tuple[int, FindingCluster]] = []
    duplicate_ordinals: dict[tuple[object, ...], int] = {}

    for index, finding in enumerate(findings):
        identity = _root_identity(finding, source_root)
        if identity is not None:
            grouped.setdefault(identity, []).append(index)
            continue

        metadata = finding.metadata or {}
        fingerprint = (
            "finding",
            _normalized_path(finding.file_path, source_root),
            finding.start_line,
            finding.rule_id,
            finding.category.value,
            str(metadata.get("caller") or ""),
            finding.message,
        )
        ordinal = duplicate_ordinals.get(fingerprint, 0)
        duplicate_ordinals[fingerprint] = ordinal + 1
        cluster_id = _digest((*fingerprint, ordinal))
        singletons.append(
            (
                index,
                FindingCluster(
                    cluster_id=cluster_id,
                    sink_file=_normalized_path(finding.file_path, source_root),
                    sink_line=finding.start_line,
                    sink_rule=finding.rule_id,
                    sink_symbol=str(metadata.get("sink_symbol") or ""),
                    member_indexes=(index,),
                    primary_index=index,
                ),
            )
        )

    clustered: list[tuple[int, FindingCluster]] = []
    for identity, indexes in grouped.items():
        sink_file, sink_line, sink_rule, sink_symbol = identity
        clustered.append(
            (
                min(indexes),
                FindingCluster(
                    cluster_id=_digest(("root", *identity)),
                    sink_file=sink_file,
                    sink_line=sink_line,
                    sink_rule=sink_rule,
                    sink_symbol=sink_symbol,
                    member_indexes=tuple(indexes),
                    primary_index=_primary_index(indexes, findings),
                ),
            )
        )

    return [cluster for _, cluster in sorted((*singletons, *clustered))]

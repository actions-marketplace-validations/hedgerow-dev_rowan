"""Rule model and loader for Rowan."""

from __future__ import annotations

import fnmatch
import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rowan.core.findings import Category, Finding, Severity
from rowan.core.sanitizers import (
    get_sanitizers_for_category,
    line_identifiers,
    sanitizer_matches,
)

logger = logging.getLogger(__name__)

_SANITIZER_WINDOW = 10

#: Kept as an alias: the identifier and sanitizer logic lives in
#: `core/sanitizers.py` since CN-04.
_line_identifiers = line_identifiers

# Cap the line length fed to regex matching. Pathologically long lines (minified
# bundles, embedded data blobs) are the primary ReDoS vector for the legacy regex
# engine and are low-value to scan; truncating bounds catastrophic-backtracking
# input while preserving line numbers.
_MAX_SCAN_LINE_LEN = 2000

# Inline suppression directives that silence a finding on the line they annotate.
#
# `noqa` is deliberately NOT honoured. It is a general-purpose Python linter
# directive (pycodestyle/pyflakes/Ruff), so treating it as a security
# suppression means `# noqa: E501` ("line too long") or `# noqa: F401`
# ("unused import") silently drops security findings that have nothing to do
# with the annotated lint. Measured on a 6-repo AI/ML corpus, ~93% of `noqa`
# directives carried a non-security code -- and the one that motivated this
# change hid an `eval()` on LLM output behind `# noqa: S307`.
#
# `nosec` is kept: unlike `noqa` it is security-intended by construction
# (bandit's own directive), so its presence is an explicit statement that a
# security finding on that line was reviewed and accepted.
INLINE_SUPPRESS_RE = re.compile(
    r"#\s*(?:nosec|rowan:disable|rowan:disable)", re.IGNORECASE
)

# Backwards-compatible private alias (this module's original spelling).
_INLINE_SUPPRESS_RE = INLINE_SUPPRESS_RE

_PLACEHOLDER_RE = re.compile(
    r"(?i)your_|changeme|xxx|dummy|foo|bar|example|test|TODO|FIXME|placeholder"
    r"|<KEY>|<TOKEN>|INSERT|REPLACE|n/a"
)
_ALL_ZEROS_RE = re.compile(r"^0{10,}$")
_ENV_REF_RE = re.compile(
    r"os\.environ|os\.getenv|process\.env|\$\{[A-Z_]+\}|getenv\(|config\.get\(|vault\.|KeyVault"
)
_SECRET_VALUE_RE = re.compile(r"""=\s*["']([^"']+)["']|=\s*(\S+)""")


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum(
        (c / length) * math.log2(c / length) for c in counts.values()
    )


def _is_placeholder(value: str) -> bool:
    if _PLACEHOLDER_RE.search(value):
        return True
    if _ALL_ZEROS_RE.match(value):
        return True
    return bool(len(value) > 1 and len(set(value)) == 1)


def _is_env_reference(line: str) -> bool:
    return bool(_ENV_REF_RE.search(line))


def _extract_secret_value(line: str) -> str:
    m = _SECRET_VALUE_RE.search(line)
    if m:
        return m.group(1) or m.group(2) or ""
    return ""


@dataclass
class RuleMetadata:
    id: str
    name: str
    severity: Severity
    category: Category
    description: str = ""
    cwe_ids: list[int] = field(default_factory=list)
    owasp_ids: list[str] = field(default_factory=list)
    languages: list[str] = field(default_factory=list)
    remediation: str = ""
    references: list[str] = field(default_factory=list)
    exclude_paths: list[str] = field(default_factory=list)


@dataclass
class RegexPattern:
    """A compiled regex pattern with its match type."""

    pattern: re.Pattern
    raw: str
    is_negative: bool = False


@dataclass
class NeuroScanRule:
    """A regex-based pattern-matching rule."""

    metadata: RuleMetadata
    patterns: list[RegexPattern] = field(default_factory=list)
    sanitizer_patterns: list[re.Pattern] = field(default_factory=list)
    message_template: str = ""

    def check(self, file_path: Path) -> list[Finding]:
        findings: list[Finding] = []
        if self.metadata.exclude_paths and self._path_excluded(file_path):
            return findings
        try:
            source = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        lines = [
            ln if len(ln) <= _MAX_SCAN_LINE_LEN else ln[:_MAX_SCAN_LINE_LEN]
            for ln in source.splitlines()
        ]
        n = len(lines)
        matched_lines: set[int] = set()
        excluded_lines: set[int] = set()

        for p in self.patterns:
            for i, line in enumerate(lines, 1):
                if p.is_negative and p.pattern.search(line):
                    excluded_lines.add(i)

        for p in self.patterns:
            if p.is_negative:
                continue
            for i, line in enumerate(lines, 1):
                if i in excluded_lines:
                    continue
                if i in matched_lines and not self.metadata.id.startswith("NS-SECRET-"):
                    continue
                if not p.pattern.search(line):
                    continue
                if _INLINE_SUPPRESS_RE.search(line):
                    continue
                if self._sanitizer_in_window(lines, i, n, line):
                    continue
                if self._is_secret_rule():
                    if _is_env_reference(line):
                        continue
                    val = _extract_secret_value(line)
                    if val and _is_placeholder(val):
                        continue
                    if val and _shannon_entropy(val) < 3.0:
                        continue
                matched_lines.add(i)
                findings.append(
                    Finding(
                        rule_id=self.metadata.id,
                        message=self.message_template or self.metadata.description,
                        severity=self.metadata.severity,
                        category=self.metadata.category,
                        file_path=str(file_path),
                        start_line=i,
                        cwe_ids=self.metadata.cwe_ids,
                        owasp_ids=self.metadata.owasp_ids,
                        engine="neuroscan",
                        metadata={
                            "rule_name": self.metadata.name,
                            "remediation": self.metadata.remediation,
                        },
                    )
                )

        return findings

    def _path_excluded(self, file_path: Path) -> bool:
        posix_path = file_path.as_posix()
        return any(
            fnmatch.fnmatch(posix_path, f"*{pat}*" if not any(c in pat for c in "*?[") else pat)
            for pat in self.metadata.exclude_paths
        )

    def _sanitizer_in_window(self, lines: list[str], line_num: int, total: int, matched_line: str) -> bool:
        own = list(self.sanitizer_patterns)
        registry = get_sanitizers_for_category(self.metadata.category)
        if not own and not registry:
            return False
        start = max(0, line_num - _SANITIZER_WINDOW - 1)
        end = min(total, line_num + _SANITIZER_WINDOW)
        window = lines[start:end]
        return sanitizer_matches(own, window, matched_line, whole_window=True) or sanitizer_matches(
            registry, window, matched_line
        )

    def _is_secret_rule(self) -> bool:
        rid = self.metadata.id
        return rid.startswith("NS-SECRET") or rid.startswith("ns-sec")


def load_neuroscan_rules(rules_path: Path) -> list[NeuroScanRule]:
    """Load NeuroScan regex rules from a YAML file."""
    if not rules_path.exists():
        return []

    with open(rules_path, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        logger.warning("Ignoring rules file %s: top level is not a mapping", rules_path)
        return []

    rules: list[NeuroScanRule] = []
    for entry in data.get("rules", []):
        rule = _parse_neuroscan_rule(entry)
        if rule:
            rules.append(rule)

    return rules


def _parse_neuroscan_rule(entry: dict[str, Any]) -> NeuroScanRule | None:
    """Parse a single NeuroScan rule entry."""
    rule_id = entry.get("id", "")
    if not rule_id:
        return None
    # Opengrep taint rules carry no regex patterns and could never match (PL-15).
    if entry.get("mode") == "taint":
        return None

    meta = entry.get("metadata", {})

    # Normalize severity (supports ERROR/WARNING/INFO from Opengrep rules too)
    raw_severity = entry.get("severity", "medium").lower()
    severity_map = {
        "error": Severity.HIGH,
        "warning": Severity.MEDIUM,
        "info": Severity.INFO,
        "experiment": Severity.INFO,
        "inventory": Severity.INFO,
    }
    if raw_severity in severity_map:
        severity = severity_map[raw_severity]
    else:
        try:
            severity = Severity(raw_severity)
        except ValueError:
            severity = Severity.MEDIUM

    # Normalize category: top-level wins, else metadata, else default 'general'
    raw_category = (entry.get("category") or meta.get("category", "general")).lower()
    try:
        category = Category(raw_category)
    except ValueError:
        category = Category.GENERAL

    # Resolve CWE: top-level wins, else metadata, else []
    cwe_ids = entry.get("cwe") or meta.get("cwe") or []

    metadata = RuleMetadata(
        id=rule_id,
        name=entry.get("name", rule_id),
        severity=severity,
        category=category,
        description=entry.get("message", ""),
        cwe_ids=cwe_ids,
        languages=entry.get("languages", []),
        remediation=entry.get("fix", "") or entry.get("remediation", "") or meta.get("fix", ""),
        exclude_paths=entry.get("exclude_paths", []),
    )

    # `patterns` means two different things depending on the engine a rule
    # targets: a list of regex STRINGS for this (NeuroScan) engine, and a list
    # of structural pattern MAPPINGS for Opengrep search-mode rules. The
    # pipeline hands every rules/*.yaml file to this loader, so a hand-written
    # Opengrep rule (rules/guardrail_opengrep.yaml, issue #186) lands here too and
    # used to crash the whole corpus load with `'dict' object has no attribute
    # 'startswith'`. Skip anything that isn't a string rather than assuming.
    raw_patterns = entry.get("patterns", [])
    declared_patterns = sum(1 for p in raw_patterns if isinstance(p, str))

    patterns: list[RegexPattern] = []
    for pat in raw_patterns:
        if not isinstance(pat, str):
            continue
        flags = 0
        # Use IGNORECASE for patterns that start with (?i) flag, otherwise case-sensitive
        if pat.startswith("(?i)"):
            flags |= re.IGNORECASE
            pat = pat[4:]  # strip the (?i) prefix
        try:
            compiled = re.compile(pat, flags)
        except re.error as e:
            logger.warning("Rule %s: invalid pattern %r skipped: %s", rule_id, pat, e)
            continue
        patterns.append(RegexPattern(pattern=compiled, raw=pat))

    # A rule whose `patterns` block held no regex strings at all is not a
    # NeuroScan rule; it belongs to another engine. Returning it with an empty
    # pattern list would register a rule that can never match while still
    # inflating rule counts, so drop it.
    if raw_patterns and declared_patterns == 0:
        logger.debug(
            "Rule %s has no regex patterns (likely an Opengrep rule); "
            "skipping for the NeuroScan engine",
            rule_id,
        )
        return None

    for pat in entry.get("pattern-not", []):
        if not isinstance(pat, str):
            continue
        flags = 0
        if pat.startswith("(?i)"):
            flags |= re.IGNORECASE
            pat = pat[4:]
        try:
            compiled = re.compile(pat, flags)
        except re.error as e:
            logger.warning("Rule %s: invalid pattern-not %r skipped: %s", rule_id, pat, e)
            continue
        patterns.append(RegexPattern(pattern=compiled, raw=pat, is_negative=True))

    return NeuroScanRule(
        metadata=metadata,
        patterns=patterns,
        sanitizer_patterns=_parse_sanitizer_patterns(rule_id, entry.get("sanitizers", [])),
        message_template=entry.get("message", ""),
    )


def _parse_sanitizer_patterns(rule_id: str, raw_sanitizers: list[str]) -> list[re.Pattern]:
    compiled: list[re.Pattern] = []
    for pat in raw_sanitizers:
        try:
            compiled.append(re.compile(pat))
        except re.error as e:
            logger.warning("Rule %s: invalid sanitizer pattern %r skipped: %s", rule_id, pat, e)
            continue
    return compiled

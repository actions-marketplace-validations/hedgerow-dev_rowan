"""Rule quality linter for rowan rule packs.

This module audits the YAML rule files shipped in ``rules/`` for quality
anti-patterns that produce huge volumes of false positives. The motivating
example is a taint rule whose ``pattern-sources`` block contained the
catch-all matcher ``$FUNC(...)`` which matches *every* function call and
therefore taints essentially everything.

Two families of rules are checked:

* **Taint rules** (``mode: taint``): every ``pattern-sources`` and
  ``pattern-sinks`` block must contain at least one pattern that is not a
  universal matcher. A block whose patterns are *all* universal matchers
  (e.g. ``$FUNC(...)``, a lone ``$X``, or a bare ``...``) is flagged.
* **NeuroScan-style rules** (top-level ``patterns:`` list of regex strings):
  a rule whose regexes are *all* trivially broad (``.*``, ``.+``, ``\\S+``,
  empty string, ...) is flagged.

Structural checks applied to every rule: missing ``id`` and duplicate ``id``
values across all files.

Usage::

    python -m rowan.tools.lint_rules [rules_dir]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from typing import Any

import yaml

DEFAULT_RULES_DIR = pathlib.Path(__file__).parents[2] / "rules"

# Patterns that, on their own, match (almost) anything. Normalized by
# stripping surrounding whitespace before comparison.
_UNIVERSAL_EXACT: frozenset[str] = frozenset(
    {
        "$FUNC(...)",
        "$F(...)",
        "$FN(...)",
        "$X",
        "$VAR",
        "$OBJ",
        "$_",
        "...",
    }
)

# A pattern that is nothing but a single metavariable, e.g. ``$ANYTHING``.
_SINGLE_METAVAR_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*$")

# A pattern that is a single metavariable applied to ``(...)``, e.g.
# ``$FUNC(...)`` / ``$G(...)``: matches every function/method call.
_METAVAR_CALL_RE = re.compile(r"^\$[A-Za-z_][A-Za-z0-9_]*\(\.\.\.\)$")

# Regexes that match (almost) anything and are therefore useless as a
# detection surface on their own.
_TRIVIAL_REGEXES: frozenset[str] = frozenset(
    {
        "",
        ".*",
        ".+",
        ".*?",
        ".+?",
        "(.*)",
        "(.+)",
        r"\S+",
        r"\s+",
        r"\w+",
        r"\S*",
        r"\w*",
    }
)

# Tokens whose presence in a NeuroScan regex pattern indicates that the
# pattern is NOT a bare framework call: it references a user-input source,
# a *dangerous* operation, or a recognised security-relevant API.  Bare
# *framework* calls (``ChatPromptTemplate(``, ``LLMChain(``) fire on every
# API usage and produce noise; deliberate danger patterns (``pickle.loads(``,
# ``eval(``) are narrow enough by their nature.
#
# Word-boundary matching is avoided here because the strings we scan are
# *regex patterns themselves* and contain backslash-prefixed regex
# metacharacters (``\\b``, ``\\B``) that confound ``\\b``-based assertions.
_CONTEXT_TOKENS: frozenset[str] = frozenset(
    {
        # user input / taint sources
        "request", "input", "inputs", "user", "argv", "environ",
        "getenv", "body", "form", "args", "json", "query",
        "recv", "stdin", "cookie", "cookies", "header", "headers",
        "payload", "session", "url", "uri",
        "source", "param", "params",
        # dangerous operations / APIs
        "exec", "eval", "pickle", "yaml", "subprocess", "popen",
        "marshal", "dill", "joblib", "shell", "command", "cmd",
        "loads", "load", "dumps", "dump",
        "deserialize", "unserialize", "unpickle",
        "unsafe", "insecure", "danger", "system",
        # HTTP clients (SSRF indicators)
        "requests", "httpx", "urllib", "axios", "fetch", "curl", "wget",
        # secrets / auth
        "token", "password", "secret", "credential", "auth", "key",
        # crypto weaknesses
        "md5", "sha1",
    }
)


def _has_context_token(pattern: str) -> bool:
    """Return True if *pattern* contains a recognised context token.

    Strips common regex metacharacter sequences (``\\b``, ``\\B``, ``\\A``,
    ``\\Z``, ``(?<![...])``, ``\\G``, ``\\<``, ``\\>``) from the pattern
    before checking because these produce pseudo-word-characters that
    confound simple boundary checks.
    """
    cleaned = re.sub(
        r"\\[bBAZzGg]|"
        r"\(\?(?:<?[=!]|P?<[^>]*>|:|!|#)[^)]*\)|"
        r"\\[<>]",
        " ",
        pattern,
    )
    pattern_lower = cleaned.lower()
    for token in _CONTEXT_TOKENS:
        pos = 0
        while True:
            pos = pattern_lower.find(token, pos)
            if pos == -1:
                break
            end = pos + len(token)
            left_ok = (pos == 0
                       or not (cleaned[pos - 1].isalnum() or cleaned[pos - 1] == '_'))
            right_ok = (end == len(cleaned)
                        or not (cleaned[end].isalnum() or cleaned[end] == '_'))
            if left_ok and right_ok:
                return True
            pos = end
    return False

# After the `\\(` part we tolerate only *generic* filler:
#   [^)]*  .*  \\s*  \\)  capture groups
# Stripped from the portion of a regex pattern that follows ``\\(`` to
# determine whether anything *specific* (as opposed to generic argument
# capture) remains.
_GENERIC_AFTER_RE = re.compile(
    r"(?:"
    r"\[\^\)\]\*|"        # [^)]*
    r"\.\*|"              # .*
    r"\\s[\*\+]|"         # \\s*  or  \\s+
    r"\\\)"               # \\)
    r")*"
)


def _is_universal_matcher(pattern: str) -> bool:
    """Return True if *pattern* matches essentially everything on its own."""
    normalized = pattern.strip()
    if normalized in _UNIVERSAL_EXACT:
        return True
    if _SINGLE_METAVAR_RE.match(normalized):
        return True
    return bool(_METAVAR_CALL_RE.match(normalized))


def _is_trivial_regex(regex: str) -> bool:
    """Return True if *regex* matches essentially everything on its own."""
    return regex.strip() in _TRIVIAL_REGEXES


def _collect_pattern_strings(node: Any) -> list[str]:
    """Recursively collect every leaf ``pattern:`` string within *node*.

    Walks the nested ``pattern-either`` / ``patterns`` structure of a taint
    source or sink block and returns the concrete pattern strings. Constraint
    keys such as ``pattern-inside`` or ``pattern-not`` are intentionally
    ignored: only primary ``pattern`` matchers are considered when deciding
    whether a block is universally broad.
    """
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "pattern" and isinstance(value, str):
                found.append(value)
            elif key == "patterns" and _is_constrained_block(value):
                # A bare `$PARAM` anchored by pattern-inside or a
                # metavariable constraint (e.g. "parameters of a @Tool
                # method") is not universal; report it as constrained so
                # the block is not flagged.
                found.extend(
                    f"{p} (constrained)" for p in _collect_pattern_strings(value)
                )
            else:
                found.extend(_collect_pattern_strings(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_collect_pattern_strings(item))
    return found


_CONSTRAINT_KEYS = frozenset({"pattern-inside", "metavariable-regex", "metavariable-pattern"})


def _is_constrained_block(patterns: Any) -> bool:
    return isinstance(patterns, list) and any(
        isinstance(item, dict) and _CONSTRAINT_KEYS & item.keys() for item in patterns
    )


def _rule_label(rule: dict, fname: str) -> str:
    return f"{fname}: rule '{rule.get('id', '<no id>')}'"


def _check_taint_block(
    rule: dict, fname: str, block_key: str, violations: list[str]
) -> None:
    block = rule.get(block_key)
    if block is None:
        return
    patterns = _collect_pattern_strings(block)
    if not patterns:
        # No concrete `pattern:` matchers (e.g. regex-only block): be
        # conservative and do not flag.
        return
    if all(_is_universal_matcher(p) for p in patterns):
        joined = ", ".join(sorted(set(patterns)))
        violations.append(
            f"{_rule_label(rule, fname)}: every {block_key} pattern is a "
            f"universal matcher ({joined}); this matches nearly everything "
            f"and must be narrowed to specific, attacker-controllable patterns"
        )


def _check_neuroscan_regexes(rule: dict, fname: str, violations: list[str]) -> None:
    patterns = rule.get("patterns")
    if not isinstance(patterns, list) or not patterns:
        return
    # Only applies to NeuroScan-style rules whose `patterns` is a flat list of
    # regex strings (taint rules use lists of dicts here).
    if not all(isinstance(p, str) for p in patterns):
        return
    if all(_is_trivial_regex(p) for p in patterns):
        joined = ", ".join(repr(p) for p in patterns)
        violations.append(
            f"{_rule_label(rule, fname)}: every regex is trivially broad "
            f"({joined}); this matches nearly everything and must be narrowed"
        )


def _is_bare_call_pattern(pattern: str) -> bool:
    """Return True if *pattern* is a bare framework call without context.

    A "bare call" is a regex pattern that matches any call to a framework
    API/constructor (``SomeClass(`` or ``module.func(``) without a
    user-input source, a dangerous-operation token, or a specific argument
    condition.  Such patterns fire on every normal-usage call-site and
    flood false positives.
    """
    idx = pattern.find(r"\(")
    if idx == -1:
        return False

    if _has_context_token(pattern):
        return False

    after = pattern[idx + 2:]  # skip the two-char sequence \(
    # Repeatedly strip generic regex filler; whatever remains indicates
    # that the pattern carries specificity.
    prev: str | None = None
    while after != prev:
        prev = after
        after = _GENERIC_AFTER_RE.sub("", after)
    if after.strip():
        return False

    # Reject patterns whose call-target portion contains suspicious markers
    # (whitespace, control chars) suggesting this isn't a clean bare-call regex.
    before = pattern[:idx]
    before_clean = re.sub(r"^(?:\\b|\(\?<![.\w\\\]]*\)|\\\\[Bb])", "", before)
    return bool(
        before_clean
        and not re.search(r"[\x00-\x08\x0e-\x1f\v\f]", before_clean)
    )


def find_broad_framework_call_patterns(
    rules_dir: pathlib.Path,
) -> list[str]:
    """Scan NeuroScan rules for regex patterns that are bare framework calls.

    Returns a list of human-readable advisory warning strings.  An empty
    list means no bare-call patterns were found.

    This is a *separate* detector from :func:`lint_rules`; it does **not**
    affect the regression tests that enforce repo cleanness.
    """
    rules_dir = pathlib.Path(rules_dir)
    warnings: list[str] = []

    for path in sorted(rules_dir.glob("*.yaml")):
        fname = path.name
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except yaml.YAMLError:
            continue

        if not isinstance(data, dict):
            continue
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            continue

        for rule in rules:
            if not isinstance(rule, dict):
                continue
            patterns = rule.get("patterns")
            if not isinstance(patterns, list) or not patterns:
                continue
            if not all(isinstance(p, str) for p in patterns):
                continue

            for p in patterns:
                if _is_bare_call_pattern(p):
                    warnings.append(
                        f"WARN(broad-call): {_rule_label(rule, fname)} "
                        f"pattern {p!r} is a bare framework call "
                        f"with no user-input / danger context token"
                    )

    return warnings


def lint_rules(rules_dir: pathlib.Path) -> list[str]:
    """Lint every ``*.yaml`` rule file in *rules_dir*.

    Returns a list of human-readable violation strings. An empty list means
    the rule packs are clean.
    """
    rules_dir = pathlib.Path(rules_dir)
    violations: list[str] = []
    seen_ids: dict[str, str] = {}

    for path in sorted(rules_dir.glob("*.yaml")):
        fname = path.name
        try:
            with open(path, encoding="utf-8") as fh:
                data = yaml.safe_load(fh)
        except yaml.YAMLError as exc:
            violations.append(f"{fname}: failed to parse YAML: {exc}")
            continue

        if not isinstance(data, dict):
            continue
        rules = data.get("rules", [])
        if not isinstance(rules, list):
            violations.append(f"{fname}: 'rules' is not a list")
            continue

        for rule in rules:
            if not isinstance(rule, dict):
                violations.append(f"{fname}: rule entry is not a mapping")
                continue

            rule_id = rule.get("id")
            if not rule_id or not isinstance(rule_id, str):
                violations.append(f"{fname}: rule missing 'id'")
            else:
                if rule_id in seen_ids:
                    violations.append(
                        f"{fname}: duplicate rule id '{rule_id}' "
                        f"(first seen in {seen_ids[rule_id]})"
                    )
                else:
                    seen_ids[rule_id] = fname

            if rule.get("mode") == "taint":
                _check_taint_block(rule, fname, "pattern-sources", violations)
                _check_taint_block(rule, fname, "pattern-sinks", violations)

            _check_neuroscan_regexes(rule, fname, violations)

    return violations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m rowan.tools.lint_rules",
        description="Lint rowan rule packs for quality anti-patterns.",
    )
    parser.add_argument(
        "rules_dir",
        nargs="?",
        default=str(DEFAULT_RULES_DIR),
        help="Directory containing *.yaml rule files (default: repo rules/).",
    )
    args = parser.parse_args(argv)

    rules_dir = pathlib.Path(args.rules_dir)
    if not rules_dir.is_dir():
        print(f"error: rules directory not found: {rules_dir}", file=sys.stderr)
        return 2

    violations = lint_rules(rules_dir)

    broad_warnings = find_broad_framework_call_patterns(rules_dir)
    if broad_warnings:
        print(
            f"Found {len(broad_warnings)} bare-framework-call advisory/ies "
            f"(these are WARNINGS only and do not affect exit code):"
        )
        for w in broad_warnings:
            print(f"  {w}")
        print()

    if violations:
        print(f"Found {len(violations)} rule quality violation(s):")
        for violation in violations:
            print(f"  - {violation}")
        return 1

    print(f"OK: no rule quality violations in {rules_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

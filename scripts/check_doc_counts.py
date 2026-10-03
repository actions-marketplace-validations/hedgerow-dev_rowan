#!/usr/bin/env python3
"""
Verify that rule and test counts in documentation match the actual source.

This script:
1. Reads rules/converted/_manifest.json for the authoritative regex rule count
2. Counts mode: taint rules by scanning rules/*.yaml files
3. Counts YAML rule files in rules/
4. Runs pytest --collect-only -q to get test count
5. Cross-checks these numbers against README.md, ARCHITECTURE.md, and docs/rules.md
6. Exits non-zero with a diff-style report if anything doesn't match
7. Exits 0 with a short "counts match" message otherwise
"""

import fnmatch
import json
import re
import subprocess
import sys
from pathlib import Path


def get_project_root() -> Path:
    """Find the project root directory."""
    current = Path(__file__).parent
    while current != current.parent:
        if (current / "rules").exists() and (current / "README.md").exists():
            return current
        current = current.parent
    raise RuntimeError("Could not find project root")


def get_regex_rule_count(root: Path) -> int:
    """Read the authoritative regex rule count from _manifest.json."""
    manifest_path = root / "rules" / "converted" / "_manifest.json"
    with open(manifest_path) as f:
        data = json.load(f)
    return data["meta"]["total_rules"]


def _is_opengrep_rule_file(yaml_file: Path) -> bool:
    """True if TaintPass loads this file into the Opengrep engine.

    Mirrors the globs in `rowan/passes/taint.py`. Classifying by filename
    rather than by the presence of `mode: taint` matters because not every
    hand-written Opengrep rule is a taint rule -- rules/guardrail_opengrep.yaml
    (issue #186) holds structural search-mode rules, which run on Opengrep but
    have no `mode: taint` line. Counting those as regex rules would attribute
    them to the wrong engine.
    """
    name = yaml_file.name
    return (
        fnmatch.fnmatch(name, "*_taint.yaml")
        or fnmatch.fnmatch(name, "*_taint_*.yaml")
        or fnmatch.fnmatch(name, "*_opengrep.yaml")
    )


def get_taint_rule_count(root: Path) -> int:
    """Count Opengrep-engine rules across rules/*.yaml files.

    That is every `mode: taint` rule, plus every rule living in an Opengrep
    rule file that does not declare a mode (search-mode structural rules).
    """
    rules_dir = root / "rules"
    taint_count = 0

    for yaml_file in rules_dir.glob("*.yaml"):
        with open(yaml_file) as f:
            content = f.read()
        # Match "mode: taint" at the start of a line (after optional whitespace)
        mode_taint = len(re.findall(r"^\s*mode: taint\s*$", content, re.MULTILINE))
        taint_count += mode_taint

        if _is_opengrep_rule_file(yaml_file):
            total_rules = len(re.findall(r"^\s*-\s+id:\s*\S+", content, re.MULTILINE))
            # Whatever is left in an Opengrep file after the taint rules are
            # accounted for is a search-mode rule on the same engine.
            taint_count += max(0, total_rules - mode_taint)

    return taint_count


def get_yaml_file_count(root: Path) -> int:
    """Count YAML rule files in rules/ directory."""
    rules_dir = root / "rules"
    yaml_files = list(rules_dir.glob("*.yaml"))
    return len(yaml_files)


def get_yaml_file_split(root: Path) -> tuple[int, int]:
    """Split rules/*.yaml into (regex_yaml_files, taint_yaml_files) counts.

    A file counts as "taint" if TaintPass loads it into the Opengrep engine --
    it contains at least one `mode: taint` rule, or its name matches the
    TaintPass globs (see `_is_opengrep_rule_file`). Computed dynamically rather
    than hardcoded so this doesn't go stale the next time a *_taint.yaml file
    is added or removed (see issue #133 / llm_output_taint.yaml).
    """
    rules_dir = root / "rules"
    regex_files = 0
    taint_files = 0
    for yaml_file in rules_dir.glob("*.yaml"):
        with open(yaml_file) as f:
            content = f.read()
        if _is_opengrep_rule_file(yaml_file) or re.search(
            r"^\s*mode: taint\s*$", content, re.MULTILINE
        ):
            taint_files += 1
        else:
            regex_files += 1
    return regex_files, taint_files


def get_test_count(root: Path) -> int:
    """Run pytest --collect-only -q and parse the test count.

    Tries this interpreter's own pytest first (works when the script is run
    via `uv run`), then falls back to `uv run pytest` (this project's own
    dependencies live in a uv-managed venv, so a bare `python`/`python3` on
    PATH will not have pytest installed), then bare python/python3 as a
    last resort for non-uv environments.
    """
    candidates = [
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        ["uv", "run", "pytest", "--collect-only", "-q"],
        ["python3", "-m", "pytest", "--collect-only", "-q"],
        ["python", "-m", "pytest", "--collect-only", "-q"],
    ]

    result = None
    for cmd in candidates:
        try:
            result = subprocess.run(  # noqa: S603 -- trusted, hardcoded doc-count commands
                cmd,
                cwd=root,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue
        if result.returncode == 0:
            break

    if result is None or result.returncode != 0:
        return None

    # Parse the final line which should be "N tests collected" or similar
    # Look for a line like "720 tests collected" or "720 tests"
    output = result.stdout + result.stderr
    matches = re.search(r"(\d+)\s+tests?\s+collected", output)
    if matches:
        return int(matches.group(1))

    return None


def search_doc_counts(doc_path: Path) -> dict:
    """Search a documentation file for count-like phrases.

    Returns a dict with keys like 'total_rules', 'regex_rules', 'taint_rules',
    'total_yaml_files', 'regex_yaml_files', 'taint_yaml_files', 'tests'
    and values like (count, line_num, context).

    Strategy: Look for GENERIC patterns and capture any count, not just expected values.
    This way we'll catch both matching and drifting counts.
    """
    counts = {}

    with open(doc_path) as f:
        lines = f.readlines()

    for line_num, line in enumerate(lines, 1):
        # Look for "NNN regex rules" or "NNN fast pattern rules" - capture any number
        if match := re.search(r"(\d+)\s+(?:regex|fast pattern)\s+rules?", line, re.IGNORECASE):
            count = int(match.group(1))
            if "regex_rules" not in counts:
                counts["regex_rules"] = (count, line_num, line.strip())

        # Look for "NNN taint rules" - capture any number
        if match := re.search(r"(\d+)\s+taint\s+rules?", line, re.IGNORECASE):
            count = int(match.group(1))
            if "taint_rules" not in counts:
                counts["taint_rules"] = (count, line_num, line.strip())

        # Look for "NNN YAML files" with explicit context. Do not infer the
        # category from digits inside a rule count: a total such as 582 also
        # contains "82", which used to misclassify it as a taint-file count.
        if match := re.search(r"(\d+)\s+YAML\s+files?", line, re.IGNORECASE):
            count = int(match.group(1))
            if "regex" in line.lower():
                if "regex_yaml_files" not in counts:
                    counts["regex_yaml_files"] = (count, line_num, line.strip())
            elif "taint" in line.lower():
                if "taint_yaml_files" not in counts:
                    counts["taint_yaml_files"] = (count, line_num, line.strip())
            else:
                if "total_yaml_files" not in counts:
                    counts["total_yaml_files"] = (count, line_num, line.strip())

        # Look for total rules count - "NNN rules across" or just "NNN rules" in a non-regex/taint context
        # Must be in a line that's NOT about specific regex/taint
        if "regex" not in line.lower() and "taint" not in line.lower():
            # Look for "NNN rules" patterns in context like "across YAML files"
            if (match := re.search(r"(\d+)\s+rules?\s+across", line)) or (match := re.search(r"^[^(regex|taint)]*(\d+)\s+rules?\s*$", line, re.IGNORECASE)):
                count = int(match.group(1))
                if count >= 350 and "total_rules" not in counts:
                    counts["total_rules"] = (count, line_num, line.strip())

        # Look for test count in pytest context
        if match := re.search(r"(\d+)\s+tests?(?:\s+collected)?", line):
            count = int(match.group(1))
            # Only count if "pytest" is nearby or we see "collected"
            context = "".join(lines[max(0, line_num-3):min(len(lines), line_num+1)])
            if "pytest" in context or "collected" in line:
                if "tests" not in counts:
                    counts["tests"] = (count, line_num, line.strip())

    return counts


def main():
    root = get_project_root()

    # Gather all counts from source
    regex_count = get_regex_rule_count(root)
    taint_count = get_taint_rule_count(root)
    yaml_count = get_yaml_file_count(root)
    regex_yaml_files, taint_yaml_files = get_yaml_file_split(root)
    test_count = get_test_count(root)

    total_rules = regex_count + taint_count

    # Gather expected counts from documentation
    readme_counts = search_doc_counts(root / "README.md")
    arch_counts = search_doc_counts(root / "ARCHITECTURE.md")
    rules_counts = search_doc_counts(root / "docs" / "rules.md")

    # Check for mismatches
    issues = []

    # Check total rules
    for doc_name, doc_counts in [("README.md", readme_counts),
                                   ("ARCHITECTURE.md", arch_counts),
                                   ("docs/rules.md", rules_counts)]:
        if "total_rules" in doc_counts:
            count, line_num, _context = doc_counts["total_rules"]
            if count != total_rules:
                issues.append(
                    f"{doc_name}:{line_num} says {count} total rules, "
                    f"but actual is {total_rules} ({regex_count} regex + {taint_count} taint)"
                )

    # Check regex rules
    for doc_name, doc_counts in [("README.md", readme_counts),
                                   ("ARCHITECTURE.md", arch_counts),
                                   ("docs/rules.md", rules_counts)]:
        if "regex_rules" in doc_counts:
            count, line_num, _context = doc_counts["regex_rules"]
            if count != regex_count:
                issues.append(
                    f"{doc_name}:{line_num} says {count} regex rules, but actual is {regex_count}"
                )

    # Check taint rules
    for doc_name, doc_counts in [("README.md", readme_counts),
                                   ("ARCHITECTURE.md", arch_counts),
                                   ("docs/rules.md", rules_counts)]:
        if "taint_rules" in doc_counts:
            count, line_num, _context = doc_counts["taint_rules"]
            if count != taint_count:
                issues.append(
                    f"{doc_name}:{line_num} says {count} taint rules, but actual is {taint_count}"
                )

    # Check YAML file counts
    for doc_name, doc_counts in [("README.md", readme_counts),
                                   ("ARCHITECTURE.md", arch_counts),
                                   ("docs/rules.md", rules_counts)]:
        # Check total YAML files.
        if "total_yaml_files" in doc_counts:
            count, line_num, _context = doc_counts["total_yaml_files"]
            if count != yaml_count:
                issues.append(
                    f"{doc_name}:{line_num} says {count} YAML files, but actual is {yaml_count}"
                )

        # Check regex-specific / taint-specific YAML file counts (computed
        # dynamically from rules/*.yaml, not hardcoded -- see
        # get_yaml_file_split).
        if "regex_yaml_files" in doc_counts:
            count, line_num, _context = doc_counts["regex_yaml_files"]
            if count != regex_yaml_files:
                issues.append(
                    f"{doc_name}:{line_num} says {count} regex YAML files, but actual is {regex_yaml_files}"
                )

        if "taint_yaml_files" in doc_counts:
            count, line_num, _context = doc_counts["taint_yaml_files"]
            if count != taint_yaml_files:
                issues.append(
                    f"{doc_name}:{line_num} says {count} taint YAML files, but actual is {taint_yaml_files}"
                )

    # Check tests (only if pytest succeeded)
    if test_count is not None:
        for doc_name, doc_counts in [("README.md", readme_counts),
                                       ("ARCHITECTURE.md", arch_counts),
                                       ("docs/rules.md", rules_counts)]:
            if "tests" in doc_counts:
                count, line_num, _context = doc_counts["tests"]
                if count != test_count:
                    issues.append(
                        f"{doc_name}:{line_num} says {count} tests, but actual is {test_count}"
                    )

    # Report results
    print("Verification Summary:")
    print("=" * 70)
    print(f"Regex rules (from rules/converted/_manifest.json):  {regex_count}")
    print(f"Taint rules (from rules/*.yaml mode: taint count):  {taint_count}")
    print(f"Total rules:                                        {total_rules}")
    print(f"YAML files in rules/:                               {yaml_count} ({regex_yaml_files} regex + {taint_yaml_files} taint)")
    if test_count is not None:
        print(f"Tests (from pytest --collect-only):                 {test_count}")
    else:
        print("Tests (from pytest --collect-only):                 [pytest not available]")
    print("=" * 70)

    if issues:
        print("\nMISMATCHES FOUND:")
        print("-" * 70)
        for issue in issues:
            print(f"  ✗ {issue}")
        print("-" * 70)
        sys.exit(1)
    else:
        print("\n✓ All counts match!")
        sys.exit(0)


if __name__ == "__main__":
    main()

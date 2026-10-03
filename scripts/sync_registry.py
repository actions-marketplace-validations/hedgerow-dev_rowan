#!/usr/bin/env python3
"""Expand shared registry fragments into the hand-written rule YAML (issue #159).

Rule files mark a managed region with sentinel comments::

    pattern-sources:
      # rowan-registry:begin source=web_request
      - patterns:
          - pattern-either:
              - pattern: request.args.get(...)
              ...
      # rowan-registry:end source=web_request

Everything between the ``begin`` and ``end`` sentinels is generated from
:mod:`rowan.rules_registry`. Opengrep ignores the sentinel comments, so the
file remains a valid rule file: the expanded block is exactly what the engine
loads. This keeps one authoritative definition (the registry) while the corpus
stays plain, comment-annotated YAML that Opengrep can read directly (no change
to how rules are loaded).

Usage::

    python scripts/sync_registry.py           # rewrite files in place
    python scripts/sync_registry.py --check    # exit 1 if anything is stale

``--check`` is what CI / the no-drift test run: it never writes, it just reports
whether every managed region already matches the registry.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

# Allow running as a plain script (python scripts/sync_registry.py).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rowan.rules_registry import render_pattern_either_block

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"

_BEGIN_RE = re.compile(r"^(?P<indent>[ ]*)#\s*rowan-registry:begin\s+(?P<kind>\w+)=(?P<name>\S+)\s*$")
_END_RE = re.compile(r"^[ ]*#\s*rowan-registry:end\s+(?P<kind>\w+)=(?P<name>\S+)\s*$")


class SyncError(RuntimeError):
    """A malformed sentinel region (unterminated / mismatched markers)."""


def _rewrite_text(text: str, path: Path) -> str:
    """Return ``text`` with every managed region re-rendered from the registry."""
    lines = text.split("\n")
    out: list[str] = []
    i = 0
    n = len(lines)
    while i < n:
        line = lines[i]
        m = _BEGIN_RE.match(line)
        if not m:
            out.append(line)
            i += 1
            continue

        indent = len(m.group("indent"))
        kind, name = m.group("kind"), m.group("name")
        # Find the matching end sentinel.
        j = i + 1
        while j < n:
            em = _END_RE.match(lines[j])
            if em:
                if (em.group("kind"), em.group("name")) != (kind, name):
                    raise SyncError(
                        f"{path}:{j + 1}: end sentinel {em.group('kind')}={em.group('name')} "
                        f"does not match begin {kind}={name} at line {i + 1}"
                    )
                break
            j += 1
        else:
            raise SyncError(
                f"{path}:{i + 1}: unterminated registry region {kind}={name} "
                "(no matching '# rowan-registry:end')"
            )

        rendered = render_pattern_either_block(kind, name, indent)
        out.append(line)  # keep the begin sentinel verbatim
        out.extend(rendered.split("\n"))
        out.append(lines[j])  # keep the end sentinel verbatim
        i = j + 1

    return "\n".join(out)


def sync_file(path: Path, *, check: bool) -> bool:
    """Sync one file. Returns True if it is (or was made) in sync.

    In ``check`` mode nothing is written; the return value reports whether the
    file already matched the registry.
    """
    original = path.read_text(encoding="utf-8")
    updated = _rewrite_text(original, path)
    if updated == original:
        return True
    if check:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def iter_rule_files() -> list[Path]:
    return sorted(RULES_DIR.glob("*.yaml"))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="report staleness, never write")
    args = parser.parse_args()

    stale: list[Path] = []
    for path in iter_rule_files():
        try:
            in_sync = sync_file(path, check=args.check)
        except SyncError as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return 2
        if not in_sync:
            stale.append(path)
            action = "STALE" if args.check else "rewrote"
            print(f"  {action}: {path.relative_to(PROJECT_ROOT)}", file=sys.stderr)

    if args.check and stale:
        print(
            f"\n{len(stale)} rule file(s) out of sync with the registry. "
            "Run: python scripts/sync_registry.py",
            file=sys.stderr,
        )
        return 1
    if not args.check:
        print(f"Registry sync complete ({len(stale)} file(s) updated).", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

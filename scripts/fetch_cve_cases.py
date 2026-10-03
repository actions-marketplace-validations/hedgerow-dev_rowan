#!/usr/bin/env python3
"""Fetch the real-CVE recall corpus (issue #105).

Clones each case in benchmark/ground_truth/cve_cases/manifest.json at its pinned
PRE-FIX commit into cache/<id>/. Checkouts are not committed; re-running is
idempotent (an already-fetched, correctly-pinned checkout is left alone).

Usage:
    python scripts/fetch_cve_cases.py [--id CVE-...] [--force]
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
CVE_DIR = PROJECT_ROOT / "benchmark" / "ground_truth" / "cve_cases"
CACHE_DIR = CVE_DIR / "cache"


def _git(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(  # noqa: S603
        ["git", *args],  # noqa: S607
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
    )


def _pinned_head(checkout: Path, commit: str) -> bool:
    if not (checkout / ".git").exists():
        return False
    head = _git("rev-parse", "HEAD", cwd=checkout)
    return head.returncode == 0 and head.stdout.strip().startswith(commit)


def fetch_case(case: dict, *, force: bool) -> bool:
    cid, repo, commit = case["id"], case["repo"], case["commit"]
    checkout = CACHE_DIR / cid
    if checkout.exists() and _pinned_head(checkout, commit) and not force:
        print(f"  [ok]    {cid}: already at {commit[:12]}")
        return True
    if checkout.exists():
        _git("clean", "-xdf", cwd=checkout)
    else:
        checkout.parent.mkdir(parents=True, exist_ok=True)
        clone = _git("clone", "--filter=blob:none", repo, str(checkout))
        if clone.returncode != 0:
            print(f"  [FAIL]  {cid}: clone failed: {clone.stderr.strip()[:200]}", file=sys.stderr)
            return False
    fetch = _git("fetch", "--depth", "1", "origin", commit, cwd=checkout)
    if fetch.returncode != 0:
        # Fall back to an unshallow fetch for hosts that reject by-SHA fetch.
        _git("fetch", "origin", cwd=checkout)
    checkout_res = _git("checkout", "--detach", commit, cwd=checkout)
    if checkout_res.returncode != 0:
        print(f"  [FAIL]  {cid}: checkout {commit[:12]} failed: "
              f"{checkout_res.stderr.strip()[:200]}", file=sys.stderr)
        return False
    print(f"  [fetch] {cid}: pinned to {commit[:12]}")
    return True


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--id", help="fetch only this case id")
    parser.add_argument("--force", action="store_true", help="re-fetch even if already pinned")
    args = parser.parse_args()

    manifest = json.loads((CVE_DIR / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest.get("cases", [])
    if args.id:
        cases = [c for c in cases if c["id"] == args.id]
    if not cases:
        print("No CVE cases to fetch (empty manifest or --id not found). "
              "See benchmark/ground_truth/cve_cases/README.md.", file=sys.stderr)
        return 0

    failures = sum(0 if fetch_case(c, force=args.force) else 1 for c in cases)
    print(f"\n{len(cases) - failures}/{len(cases)} case(s) ready in {CACHE_DIR}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

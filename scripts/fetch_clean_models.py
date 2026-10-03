#!/usr/bin/env python3
"""Downloads the clean-model benchmark corpus, verifying each file's SHA-256
against benchmark/ground_truth/clean_models/manifest.json before caching it.

Usage: uv run python scripts/fetch_clean_models.py
"""

from __future__ import annotations

import hashlib
import json
import urllib.request
from pathlib import Path

MANIFEST_PATH = (
    Path(__file__).parent.parent / "benchmark" / "ground_truth" / "clean_models" / "manifest.json"
)
CACHE_DIR = MANIFEST_PATH.parent / "cache"


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    CACHE_DIR.mkdir(parents=True, exist_ok=True)

    ok = True
    for entry in manifest["models"]:
        dest = CACHE_DIR / entry["cache_filename"]
        if dest.exists() and sha256_of(dest) == entry["sha256"]:
            print(f"  cached & verified: {entry['name']}")
            continue

        print(f"  fetching {entry['name']} ...")
        urllib.request.urlretrieve(entry["url"], dest)  # noqa: S310 -- fixed HTTPS URLs from the manifest
        actual = sha256_of(dest)
        if actual != entry["sha256"]:
            print(f"    HASH MISMATCH for {entry['name']}: expected {entry['sha256']}, got {actual}")
            dest.unlink(missing_ok=True)
            ok = False
        else:
            print(f"    OK ({dest.stat().st_size} bytes)")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Check that a built wheel contains runtime data and no draft rule files."""

from __future__ import annotations

import sys
from pathlib import Path
from zipfile import ZipFile


def main(wheel: Path) -> None:
    with ZipFile(wheel) as archive:
        names = set(archive.namelist())

    rules_root = Path(__file__).resolve().parents[1] / "rules"
    required = {
        "rowan/config/thresholds.yaml",
        "rules/neuroscan.yaml",
        "rules/converted/_manifest.json",
    }
    required.update(f"rules/{path.name}" for path in rules_root.glob("*.yaml"))
    required.update(f"rules/converted/{path.name}" for path in (rules_root / "converted").glob("*.yaml"))
    missing = required - names
    drafts = sorted(name for name in names if name.startswith("rules/_wip/"))
    if missing or drafts:
        if missing:
            print(f"Missing runtime files: {sorted(missing)}", file=sys.stderr)
        if drafts:
            print(f"Draft files in wheel: {drafts}", file=sys.stderr)
        raise SystemExit(1)
    print(f"Wheel contents OK: {wheel.name}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python scripts/check_distribution.py WHEEL")
    main(Path(sys.argv[1]))

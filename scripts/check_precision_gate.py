"""OS-05 precision gate for a pinned real-repository scan.

Usage: python scripts/check_precision_gate.py REPORT.json CHECKOUT_DIR REPO_NAME

REPORT.json must come from the command in benchmark/precision_gate.json. The
gate fails on a checkout that is not at the pinned revision, a report that is
degraded, incomplete or filtered, or any HIGH/CRITICAL finding that has not
been reviewed and listed under the repository's adjudicated_high.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

GATE_PATH = Path(__file__).resolve().parents[1] / "benchmark" / "precision_gate.json"


def check(report: dict, checkout: Path, entry: dict) -> list[str]:
    problems: list[str] = []
    git = shutil.which("git")
    if git is None:
        raise SystemExit("git is required to check the pinned revision")
    head = subprocess.run(  # noqa: S603 -- fixed git argv; no shell involved
        [git, "-C", str(checkout), "rev-parse", "HEAD"],
        check=True, capture_output=True, text=True,
    ).stdout.strip()
    if not head.startswith(entry["revision"]):
        problems.append(f"checkout is at {head[:12]}, gate pins {entry['revision']}")
    if report["report_view"] != "full":
        problems.append(f"report view is {report['report_view']!r}; scan with --audit")
    if report["summary"]["degraded"] or report["coverage_summary"]["status"] != "complete":
        problems.append("scan is degraded or coverage is incomplete")

    reviewed = {(item["rule_id"], item["path"], item["line"]) for item in entry["adjudicated_high"]}
    root = checkout.resolve()
    for finding in report["findings"]:
        if finding["severity"] not in ("high", "critical"):
            continue
        path = Path(finding["file"]).resolve().relative_to(root).as_posix()
        if (finding["rule_id"], path, finding["line"]) not in reviewed:
            problems.append(
                f"unreviewed {finding['severity']}: {finding['rule_id']} {path}:{finding['line']}"
            )
    return problems


def main(report_path: Path, checkout: Path, repo_name: str) -> None:
    entry = json.loads(GATE_PATH.read_text(encoding="utf-8"))["repos"][repo_name]
    report = json.loads(report_path.read_text(encoding="utf-8"))
    problems = check(report, checkout, entry)
    for problem in problems:
        print(f"FAIL {repo_name}: {problem}", file=sys.stderr)
    if problems:
        raise SystemExit(1)
    print(f"PASS {repo_name}: no unreviewed HIGH/CRITICAL at {entry['revision']}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        raise SystemExit(__doc__)
    main(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])

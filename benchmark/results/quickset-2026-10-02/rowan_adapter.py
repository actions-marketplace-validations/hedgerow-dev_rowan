"""Run quickset with a Rowan adapter added next to the existing scanners.

Usage, from a quickset checkout: ROWAN=/path/to/rowan python rowan_adapter.py --json out.json

Same subprocess contract as quickset's HaywardAdapter. `rowan scan` takes a
directory, so each file is copied alone into a fresh temp directory: one file
in, one report out, no sibling files visible.

Strict = any non-INFO finding. Lenient = any finding, INFO included.
A file whose only findings are coverage rules (file not fully read) is a
no-verdict, never a detection.
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

import quickset.adapters as qa
import quickset.run as qr

ROWAN = os.environ.get("ROWAN", "rowan")
COVERAGE_RULES = frozenset({
    "MFV-SKIP-001", "MFV-SKIP-002", "MFV-SKIP-003", "MFV-7Z-001", "MFV-GGUF-004",
})


class RowanAdapter(qa.Adapter):
    def __init__(self) -> None:
        object.__setattr__(self, "name", "rowan")
        object.__setattr__(self, "license", "MIT")
        object.__setattr__(self, "executable", ROWAN)

    def scan(self, path: Path) -> qa.ScanOutcome:
        with tempfile.TemporaryDirectory(prefix="qs-rowan-") as tmp:
            shutil.copy2(path, Path(tmp) / path.name)
            proc = self._run(
                self.executable, "scan", tmp, "--audit", "-f", "json",
                "--no-sca", "--no-taint", "--no-cross-file", "--no-project-config",
            )
        if proc.returncode == qa.TIMED_OUT_RETURNCODE:
            return qa.ScanOutcome(flagged=False, detail="timed out", errored=True)
        try:
            report = json.loads(proc.stdout)
        except (json.JSONDecodeError, ValueError):
            return qa.ScanOutcome(flagged=False, detail="unparseable report", errored=True)
        if report.get("summary", {}).get("degraded"):
            return qa.ScanOutcome(flagged=False, detail="degraded scan", errored=True)

        findings_all = [f for f in report.get("findings", []) if f.get("rule_id") not in COVERAGE_RULES]
        gaps = [f for f in report.get("findings", []) if f.get("rule_id") in COVERAGE_RULES]
        if not findings_all and gaps:
            return qa.ScanOutcome(flagged=False, detail="coverage gap, file not fully read", errored=True)
        strict = [f for f in findings_all if str(f.get("severity", "")).lower() != "info"]
        if not strict:
            return qa.ScanOutcome(flagged=False, flagged_lenient=bool(findings_all))
        order = ["info", "low", "medium", "high", "critical"]
        top = max(strict, key=lambda f: order.index(str(f.get("severity", "info")).lower()))
        return qa.ScanOutcome(
            flagged=True, detail=f"{top.get('rule_id')} / {top.get('severity')}", flagged_lenient=True,
        )


_original = qa.all_adapters


def all_adapters():
    return [*_original(), RowanAdapter()]


qa.all_adapters = all_adapters
qr.all_adapters = all_adapters

if __name__ == "__main__":
    sys.exit(qr.main())

"""Model File Validation pass: scans model files with Hayward.

Rowan's file-scan stage discovers the model artifacts (skipping virtualenvs
and vendored dependency directories) and this pass hands each one to Hayward,
Hedgerow's model-file scanner. `--exclude` and `.rowanignore` apply, with
`.rowanignore` ignored under `--ci`.
"""

from __future__ import annotations

import logging
import time

import hayward

from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.passes.base import ScanContext, SourceInventory, scan_span

logger = logging.getLogger(__name__)


def _to_rowan(finding: hayward.Finding) -> Finding:
    return Finding(
        rule_id=finding.rule_id,
        message=finding.message,
        severity=Severity(finding.severity.value),
        category=Category(finding.category.value),
        file_path=finding.file_path,
        start_line=0,
        confidence=finding.confidence,
        cwe_ids=list(finding.cwe_ids),
        metadata=dict(finding.metadata),
        engine="mfv",
    )


class ModelFileScanPass:
    name = "mfv"

    def __init__(self):
        self._scanner = hayward.ModelFileScanner()

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()

        inventory = getattr(context, "source_inventory", None)
        if isinstance(inventory, SourceInventory):
            raw = [f for path in inventory.model_artifacts for f in self._scanner.scan_file(path)]
        else:
            raw = self._scanner.scan_directory(context.target_path)
        findings = [_to_rowan(f) for f in raw]
        result = ScanResult(findings=findings)

        # MFV skip findings mean a model artifact was not fully analysed.  They
        # are intentionally LOW severity so they do not look like a confirmed
        # backdoor, but report views commonly hide LOW findings.  Preserve the
        # coverage signal independently so a quiet actionable report cannot be
        # mistaken for a complete clean scan.
        coverage_skips = [finding for finding in findings if finding.rule_id.startswith("MFV-SKIP-")]
        if coverage_skips:
            skip_reasons = sorted({finding.rule_id for finding in coverage_skips})
            result.degraded_passes["mfv"] = (
                f"model-file analysis was incomplete for {len(coverage_skips)} artifact(s) "
                f"({', '.join(skip_reasons)})"
            )
            result.metadata["mfv_coverage"] = {
                "status": "incomplete",
                "skipped_artifacts": len(coverage_skips),
                "skip_reasons": skip_reasons,
            }

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("MFVPass: %d alerts in %.1fs", len(findings), duration)
        return result

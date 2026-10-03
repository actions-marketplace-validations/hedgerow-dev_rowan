"""Instruction-smuggling pass: reports Unicode-smuggled instruction overrides
in agent instruction / prose files (LangFail V32)."""

from __future__ import annotations

import logging
import time

from rowan.analysis.unicode_smuggling import scan_directory
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext, scan_span

logger = logging.getLogger(__name__)


class InstructionSmugglingPass:
    name = "instruction_smuggling"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()

        candidates = None
        if context.source_inventory is not None:
            prose_languages = {"ai_instructions", "markdown", "text"}
            candidates = tuple(
                source.path
                for source in context.source_inventory.files
                if source.languages & prose_languages
            )
        findings = scan_directory(
            context.target_path,
            candidates,
            context.source_snapshot.read_text if candidates is not None else None,
        )
        result = ScanResult(findings=findings)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info(
            "InstructionSmugglingPass: %d alerts in %.1fs", len(findings), duration
        )
        return result

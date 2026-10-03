"""MCP config scan pass: scans MCP client config JSON for hardcoded
secrets and over-privileged server invocations."""

from __future__ import annotations

import logging
import time

from rowan.core.findings import ScanResult
from rowan.core.mcp_config import scan_directory
from rowan.passes.base import ScanContext, SourceInventory, scan_span

logger = logging.getLogger(__name__)


class MCPConfigScanPass:
    name = "mcpconfig"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()

        inventory = getattr(context, "source_inventory", None)
        if not isinstance(inventory, SourceInventory):
            inventory = None
        findings = scan_directory(
            context.target_path,
            None if inventory is None else inventory.mcp_config_files,
        )
        result = ScanResult(findings=findings)

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("MCPConfigScanPass: %d alerts in %.1fs", len(findings), duration)
        return result

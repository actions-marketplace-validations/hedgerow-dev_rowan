"""MCP tool-metadata TOCTOU pass: reports post-registration mutation of an
MCP tool's advertised description / input schema (LangFail V59)."""

from __future__ import annotations

import logging
import time

from rowan.core.findings import ScanResult
from rowan.core.mcp_tool_metadata import scan_directory, scan_tree
from rowan.passes.base import ScanContext, SourceInventory, scan_span

logger = logging.getLogger(__name__)


class MCPToolMetadataPass:
    name = "mcp_tool_metadata"

    def run(self, context: ScanContext) -> ScanResult:
        start = time.perf_counter()

        inventory = getattr(context, "source_inventory", None)
        if not isinstance(inventory, SourceInventory):
            inventory = None
        candidates = (
            None if inventory is None else inventory.paths_for("python", suffix=".py")
        )
        if candidates is None:
            findings = scan_directory(context.target_path)
        else:
            findings = []
            for path in candidates:
                tree = context.source_snapshot.python_ast(path)
                if tree is not None:
                    findings.extend(scan_tree(path, tree))
        result = ScanResult(
            findings=findings,
            files_scanned=0 if candidates is None else len(candidates),
        )

        duration = time.perf_counter() - start
        scan_span(self.name, duration)
        logger.info("MCPToolMetadataPass: %d alerts in %.1fs", len(findings), duration)
        return result

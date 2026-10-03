"""MCP evidence server: Rowan's computed facts as a tool for agentic reviewers.

Exposes one tool, `scan_evidence`, over MCP stdio. The payload is the same
JSON the CLI reporter emits: findings with per-finding `evidence_tier`
(taint-flow / engine / self-evident / pattern-only), full taint flows, and
the analysis-capability manifest saying which languages got dataflow analysis
versus patterns only. The intended consumer is an LLM reviewer that writes
the judgment itself and calls this for verifiable dataflow facts instead of
inferring them.

Requires the optional `mcp` dependency: pip install "rowan[mcp]".
Run with: rowan-mcp
"""

from __future__ import annotations

import json
import multiprocessing
import os
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.paths import is_within_root
from rowan.pipeline import ScanPipeline
from rowan.reporters import to_json

_DEFAULT_TIMEOUT_SECONDS = 600.0


def _allowed_roots() -> list[Path]:
    """`ROWAN_MCP_ROOTS` (os.pathsep-separated), else the server's cwd.

    A prompt-injected agent must not be able to point the tool at `~` or a
    sibling repository and read matched source lines back.
    """
    raw = os.environ.get("ROWAN_MCP_ROOTS", "")
    roots = [Path(r).expanduser() for r in raw.split(os.pathsep) if r.strip()]
    return [r.resolve() for r in roots] or [Path.cwd().resolve()]


def _scan_to_json(target: str) -> str:
    # ci_mode: the repository is untrusted, so its own .rowanignore and
    # fingerprint ignore file must not hide anything from the agent.
    config = ScanConfig(target=Path(target), no_sca=True, report_view="actionable", ci_mode=True)
    result = ScanPipeline(config).run()
    result.metadata["entrypoint_policy"] = {
        "name": "mcp_scan_evidence",
        "intentional_deltas": {
            "sca": "disabled_offline",
            "report_view": "actionable",
            "project_config": "not_loaded",
            "repo_ignore_files": "not_trusted",
        },
    }
    return to_json(result)


def collect_evidence(target: str) -> dict:
    """Scan `target` and return the reporter's JSON payload as a dict.

    SCA is disabled: the oracle serves code-level dataflow facts and must not
    depend on network access to OSV. Cross-file taint stays on. The target
    must sit inside an allowed root, and the scan runs in a worker process
    that is killed after `ROWAN_MCP_TIMEOUT` seconds.
    """
    target_path = Path(target).expanduser()
    roots = _allowed_roots()
    if not any(is_within_root(target_path, root) for root in roots):
        return {
            "error": (
                f"target is outside the allowed roots: {target}. Allowed: "
                f"{os.pathsep.join(map(str, roots))} (set ROWAN_MCP_ROOTS to change)"
            )
        }
    if not target_path.exists():
        hint = ""
        if not target_path.is_absolute():
            hint = (
                " (relative paths resolve against the MCP server process's "
                "working directory, not the client's -- pass an absolute path)"
            )
        return {"error": f"target does not exist: {target}{hint}"}
    if not target_path.is_dir():
        return {
            "error": (
                f"target is a file, but scan_evidence currently supports directories only: {target}. "
                "Pass the project directory so code and model-file passes share one scan scope."
            )
        }
    raw_timeout = os.environ.get("ROWAN_MCP_TIMEOUT", "")
    try:
        timeout = float(raw_timeout) if raw_timeout else _DEFAULT_TIMEOUT_SECONDS
    except ValueError:
        return {"error": f"ROWAN_MCP_TIMEOUT is not a number: {raw_timeout!r}"}
    try:
        # Scan the resolved path that passed the root check, and leave the
        # pool on exit so a timed-out worker is terminated.
        with multiprocessing.get_context("spawn").Pool(1) as pool:
            payload = pool.apply_async(_scan_to_json, (str(target_path.resolve()),)).get(timeout)
        return json.loads(payload)
    except multiprocessing.TimeoutError:
        return {"error": f"scan timed out after {timeout:g}s (ROWAN_MCP_TIMEOUT)"}
    except Exception as exc:
        # An MCP stdio transport must survive a failed scan so the client can
        # correct its input or continue with other tools in the same session.
        return {"error": f"scan failed: {type(exc).__name__}: {exc}"}


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise SystemExit(
            'The MCP server needs the optional mcp dependency: pip install "rowan[mcp]"'
        ) from exc

    server = FastMCP("rowan")

    @server.tool()
    def scan_evidence(target: str) -> dict:
        """Scan a directory and return verified security dataflow facts.

        `target` must be an ABSOLUTE path (relative paths resolve against the
        server process, not the caller). File targets are rejected instead of
        returning an incomplete clean result; pass the containing project
        directory.

        Every finding carries an evidence_tier saying how much was actually
        computed: "taint-flow" (a source-to-sink dataflow, included in the
        payload -- act on these), "engine" (model-file opcode or authz-graph
        analysis), "self-evident" (the matched text itself is the whole claim, e.g. a
        hardcoded secret or weak-crypto call -- no dataflow asserted or
        needed), or "pattern-only" (unverified pattern match; treat as a
        hypothesis, not a fact). The analysis_capability manifest names
        languages that got patterns-only coverage, where absence of findings
        is NOT evidence of absence. Large repositories can take minutes to
        scan.
        """
        return collect_evidence(target)

    server.run()


if __name__ == "__main__":
    main()

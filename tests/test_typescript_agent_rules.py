"""TypeScript agent-boundary rules: MCP, Vercel AI SDK, LangChain.js, model output."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "benchmark" / "ground_truth" / "ts_agent_cases"

pytestmark = pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep binary is required"
)


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location("benchmark_ts_agent", ROOT / "scripts" / "benchmark.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_ts_agent"] = module
    spec.loader.exec_module(module)
    return module


def test_ts_agent_pairs_detect_only_vulnerable_files():
    report = _load_benchmark_module().run_ts_agent_cases(CORPUS)
    assert not report["degraded"]
    assert report["hits"] == report["total"] == 19
    assert report["false_positives"] == 0


def test_mcp_tool_ssrf_stays_high_in_a_library_without_web_imports(tmp_path):
    # An MCP server imports no web framework and can auto-detect as a
    # library; the tool argument itself is the external boundary.
    shutil.copy(CORPUS / "typescript" / "mcp_lowlevel_fetch_vulnerable.ts", tmp_path / "server.ts")

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    [finding] = [f for f in result.findings if f.rule_id == "TNT-TS-AGENT-SSRF-001"]
    assert finding.severity == Severity.HIGH
    assert finding.metadata["evidence_tier"] == "taint-flow"


def test_graphql_object_query_is_not_sql_text(tmp_path):
    (tmp_path / "docs.ts").write_text(
        'import { tool } from "ai";\n'
        "export const searchDocs = tool({\n"
        "  execute: async ({ graphql_query }) => client.query({ query: graphql_query }),\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    assert not [f for f in result.findings if f.rule_id == "TNT-TS-AGENT-SQLI-001"]


def test_confining_helper_assigned_later_sanitizes_the_path(tmp_path):
    # Opengrep anchors metavariable-regex at the start of the callee name, so
    # the camelCase `...Confined...` form needs its own leading `.*`.
    (tmp_path / "server.ts").write_text(
        'server.tool("import", { filePath: z.string() }, async ({ filePath }) => {\n'
        "  let safePath: string;\n"
        "  safePath = resolveConfinedImportPath(filePath);\n"
        '  return fs.readFileSync(safePath, "utf8");\n'
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    assert not [f for f in result.findings if f.rule_id == "TNT-TS-AGENT-PATH-001"]


def test_assert_style_validators_clean_the_tool_argument(tmp_path):
    # A validator that throws (`validateMode(mode);`) cleans its argument for
    # the rest of the function, including inside a helper that validates
    # before building the path. The unguarded handler still reports.
    (tmp_path / "state.ts").write_text(
        "function getStatePath(mode: string): string {\n"
        "  validateMode(mode);\n"
        "  return path.join(getStateDir(), `${mode}-state.json`);\n"
        "}\n"
        'server.tool("clear", { mode: z.string() }, async ({ mode }) => {\n'
        "  fs.unlinkSync(getStatePath(mode));\n"
        "});\n"
        'server.tool("clear_raw", { mode: z.string() }, async ({ mode }) => {\n'
        "  fs.unlinkSync(path.join(getStateDir(), mode));\n"
        "});\n"
        'server.tool("clear_checked", { mode: z.string() }, async ({ mode }) => {\n'
        "  assertSafeName(mode);\n"
        "  fs.unlinkSync(path.join(getStateDir(), mode));\n"
        "});\n",
        encoding="utf-8",
    )

    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, report_view="full")).run()

    lines = sorted(f.start_line for f in result.findings if f.rule_id == "TNT-TS-AGENT-PATH-001")
    assert lines == [9]

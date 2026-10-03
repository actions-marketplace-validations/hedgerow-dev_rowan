"""BACKLOG.md JG-15: Java/Go application guards for path, SSRF and command
findings.

`rowan/core/sanitizers.py`'s `SANITIZER_REGEX` table (sourced from
`rowan/rules_registry.py`) is Python-idiom only and is consumed by
`EnrichmentPass._suppress_sanitizer_window`, which explicitly skips every
finding that carries a `taint_flow` (`f.engine != "opengrep" or
f.taint_flow is not None: continue`) -- routing those to the AST-based
`guard_clause.py` post-filter instead. `guard_clause.py` parses with
Python's own `ast` module, which raises `SyntaxError` on Java/Go source, so
for the `tnt-ja-ai-*` / `tnt-go-ai-*` taint rules (all `mode: taint`,
so every finding carries a `taint_flow`) NEITHER existing sanitizer path is
reachable: the SANITIZER_REGEX table has no consumer that ever sees these
findings, regardless of what patterns it holds.

The fix (`EnrichmentPass._demote_java_go_guarded_findings`) therefore lives
in `rowan/passes/enrichment.py`, not `core/sanitizers.py`: a small,
self-contained post-filter mirroring the same text-window +
variable-correlation shape `_sanitizer_window_matches` already uses for the
Python path, but DEMOTING (never suppressing) a Java/Go path/SSRF/
command-injection finding when an application guard correlates with the
sink's own variable. These tests run the full `EnrichmentPass` (not just the
static helper) end to end, the same way `test_enrichment_java_go_ai.py`
does, so the AI-context gate and the rest of the pipeline are exercised too.

A second, independent gap surfaced while scanning real corpus repos:
`rowan.taint.opengrep_adapter._infer_category` never resolves
`tnt-{ja,go}-ai-{tool,mcptool,llmout}-{path,exec}-*` to
`Category.PATH_TRAVERSAL`/`COMMAND_INJECTION` (the rule ids/messages don't
contain "path.traversal" or "shell"/"subprocess", and the rules' own
`category: security` metadata isn't a valid `Category` value), so every
real finding from those rules carries `category=general` and the dispatch
above would never even reach the guard-evidence check. SSRF is unaffected
(the rule ids contain "ssrf", which the shared inference table does match).
`TestCategoryFallback` below pins the rule-id-based workaround added for
this (`_AI_TAINT_RULE_RE`) directly in `EnrichmentPass`, since fixing the
shared inference table in `opengrep_adapter.py` is out of scope here.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.passes.enrichment import EnrichmentPass

SPRING_AI_IMPORT = "import org.springframework.ai.chat.client.ChatClient;\n"
MCP_GO_IMPORT = '    "github.com/mark3labs/mcp-go/mcp"\n'


def _java_src(body: str) -> str:
    return f"package demo;\n\n{SPRING_AI_IMPORT}\npublic class Tool {{\n{body}\n}}\n"


def _go_src(body: str, *, web_import: bool = False) -> str:
    # `_suppress_web_rules_on_non_web_files` gates the SSRF category on a
    # recognized web-framework import (`_WEB_IMPORT_RE`); mcp-go alone does
    # not count, so SSRF fixtures need a quoted "net/http" import too.
    extra = '\t"net/http"\n' if web_import else ""
    return (
        "package main\n\nimport (\n\t\"context\"\n\t\"os/exec\"\n"
        f"{extra}\n{MCP_GO_IMPORT})\n\n{body}\n"
    )


@pytest.fixture
def src_dir(tmp_path_factory):
    """No `test` in the path: `_suppress_test_findings` treats that as test
    code and demotes independently of the mechanism under test here."""
    return tmp_path_factory.mktemp("javago_san")


def _run_enrichment(findings: list[Finding]) -> list[Finding]:
    ctx = type("Ctx", (), {
        "target_path": Path("."),
        "config": ScanConfig(target=Path(".")),
        "result": ScanResult(findings=findings),
        "metadata": {},
    })()
    EnrichmentPass().run(ctx)
    return ctx.result.findings


def _taint_finding(
    rule_id: str, path: Path, category: Category, *, sink_line: int, snippet: str
) -> Finding:
    return Finding(
        rule_id=rule_id, message="m", severity=Severity.HIGH, category=category,
        file_path=str(path), start_line=sink_line, engine="opengrep", confidence=0.9,
        taint_flow=TaintFlow(
            source=TaintNode(file_path=str(path), line=sink_line, snippet=snippet),
            sink=TaintNode(file_path=str(path), line=sink_line),
            intermediate=[],
        ),
        metadata={"source_kind": "tool_param"},
    )


class TestPathTraversal:
    def test_java_guard_immediately_before_sink_demotes(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void read(String raw) {\n"
            "    String safe = WorkspacePathGuard.validatePath(raw);\n"
            "    java.nio.file.Files.readString(java.nio.file.Path.of(safe));\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolpath-001", path, Category.PATH_TRAVERSAL,
                            sink_line=8, snippet="raw")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.confidence <= 0.35
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_go_guard_immediately_before_sink_demotes(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    raw := req.GetString(\"path\", \"\")\n"
            "    safe := t.ws.resolve(raw)\n"
            "    os.ReadFile(safe)\n"
            "}"
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-path-001", path, Category.PATH_TRAVERSAL,
                            sink_line=13, snippet='req.GetString("path", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.confidence <= 0.35
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_java_no_guard_stays_high(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void read(String raw) {\n"
            "    java.nio.file.Files.readString(java.nio.file.Path.of(raw));\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolpath-001", path, Category.PATH_TRAVERSAL,
                            sink_line=7, snippet="raw")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH
        assert "guard_effect" not in out.metadata

    def test_go_guard_on_different_variable_stays_high(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    raw := req.GetString(\"path\", \"\")\n"
            "    cache := req.GetString(\"cache\", \"\")\n"
            "    _ = t.ws.resolve(cache)\n"
            "    os.ReadFile(raw)\n"
            "}"
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-path-001", path, Category.PATH_TRAVERSAL,
                            sink_line=14, snippet='req.GetString("path", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH, (
            "a guard on 'cache' must not demote the finding for 'raw'"
        )
        assert "guard_effect" not in out.metadata


class TestSsrf:
    def test_java_guard_immediately_before_sink_demotes(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void fetch(String target) {\n"
            "    String host = URI.create(target).getHost();\n"
            "    if (!allowedHosts.contains(host)) throw new SecurityException();\n"
            "    httpClient.send(target);\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolssrf-001", path, Category.SSRF,
                            sink_line=9, snippet="target")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_go_guard_immediately_before_sink_demotes(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    target := req.GetString(\"url\", \"\")\n"
            "    parsed, err := url.Parse(target)\n"
            "    if err != nil || !slices.Contains(allowedHosts, parsed.Host) { return }\n"
            "    http.Get(target)\n"
            "}",
            web_import=True,
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-ssrf-001", path, Category.SSRF,
                            sink_line=15, snippet='req.GetString("url", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_java_no_guard_stays_high(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void fetch(String target) {\n"
            "    httpClient.send(target);\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolssrf-001", path, Category.SSRF,
                            sink_line=7, snippet="target")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH
        assert "guard_effect" not in out.metadata

    def test_go_guard_on_different_variable_stays_high(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    target := req.GetString(\"url\", \"\")\n"
            "    other := req.GetString(\"other\", \"\")\n"
            "    parsed, err := url.Parse(other)\n"
            "    if err != nil || !slices.Contains(allowedHosts, parsed.Host) { return }\n"
            "    http.Get(target)\n"
            "}",
            web_import=True,
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-ssrf-001", path, Category.SSRF,
                            sink_line=16, snippet='req.GetString("url", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH, (
            "a guard on 'other' must not demote the finding for 'target'"
        )
        assert "guard_effect" not in out.metadata


class TestCommandInjection:
    def test_java_guard_immediately_before_sink_demotes(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void run(String cmd) {\n"
            "    if (!java.util.Set.of(\"ls\", \"pwd\").contains(cmd)) throw new SecurityException();\n"
            "    new ProcessBuilder(cmd).start();\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolexec-001", path, Category.COMMAND_INJECTION,
                            sink_line=8, snippet="cmd")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_go_guard_immediately_before_sink_demotes(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    cmd := req.GetString(\"cmd\", \"\")\n"
            "    if !regexp.MustCompile(`^[a-z]+$`).MatchString(cmd) { return }\n"
            "    exec.Command(cmd).Run()\n"
            "}"
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-exec-001", path, Category.COMMAND_INJECTION,
                            sink_line=13, snippet='req.GetString("cmd", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_java_no_guard_stays_high(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void run(String cmd) {\n"
            "    new ProcessBuilder(cmd).start();\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolexec-001", path, Category.COMMAND_INJECTION,
                            sink_line=7, snippet="cmd")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH
        assert "guard_effect" not in out.metadata

    def test_go_guard_on_different_variable_stays_high(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    cmd := req.GetString(\"cmd\", \"\")\n"
            "    other := req.GetString(\"other\", \"\")\n"
            "    if !regexp.MustCompile(`^[a-z]+$`).MatchString(other) { return }\n"
            "    exec.Command(cmd).Run()\n"
            "}"
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-exec-001", path, Category.COMMAND_INJECTION,
                            sink_line=14, snippet='req.GetString("cmd", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH, (
            "a guard on 'other' must not demote the finding for 'cmd'"
        )
        assert "guard_effect" not in out.metadata


class TestCategoryFallback:
    """`_infer_category` (opengrep_adapter.py) resolves the real
    `tnt-ja-ai-toolpath-001` / `tnt-go-ai-mcptool-path-001` /
    `tnt-*-ai-*-exec-*` findings to `category=general`, not
    `PATH_TRAVERSAL`/`COMMAND_INJECTION` -- confirmed by scanning
    yu-ai-agent and mcp-shell directly. Pass `Category.GENERAL` here (as the
    real pipeline does) to prove `_demote_java_go_guarded_findings` still
    reaches these rules via its own `_AI_TAINT_RULE_RE` rule-id fallback,
    not just when a test hand-sets the "correct" category."""

    def test_real_toolpath_rule_id_with_general_category_still_demotes(self, src_dir):
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void read(String raw) {\n"
            "    String safe = WorkspacePathGuard.validatePath(raw);\n"
            "    java.nio.file.Files.readString(java.nio.file.Path.of(safe));\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-toolpath-001", path, Category.GENERAL,
                            sink_line=8, snippet="raw")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_real_mcptool_exec_rule_id_with_general_category_still_demotes(self, src_dir):
        path = src_dir / "t.go"
        path.write_text(_go_src(
            "func handle(ctx context.Context, req mcp.CallToolRequest) {\n"
            "    cmd := req.GetString(\"cmd\", \"\")\n"
            "    if !regexp.MustCompile(`^[a-z]+$`).MatchString(cmd) { return }\n"
            "    exec.Command(cmd).Run()\n"
            "}"
        ), encoding="utf-8")
        f = _taint_finding("tnt-go-ai-mcptool-exec-001", path, Category.GENERAL,
                            sink_line=13, snippet='req.GetString("cmd", "")')
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.LOW
        assert out.metadata.get("guard_effect") == "demoted_not_suppressed"

    def test_non_ai_general_category_rule_is_untouched(self, src_dir):
        """The rule-id fallback must be scoped to the `tnt-{ja,go}-ai-`
        prefix -- an unrelated general-category finding on a .java file must
        not suddenly start being checked for a path guard."""
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  void read(String raw) {\n"
            "    java.nio.file.Files.readString(java.nio.file.Path.of(raw));\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("NS-SOME-OTHER-001", path, Category.GENERAL,
                            sink_line=7, snippet="raw")
        (out,) = _run_enrichment([f])
        assert "guard_effect" not in out.metadata

    def test_java_workspace_resolve_is_not_a_guard(self, src_dir):
        """`java.nio.file.Path.resolve(String)` is the stdlib's raw
        path-join with no validation -- it is NOT the same idiom as Go's
        `ws.resolve` (a custom, validating helper by the mcp-shell
        evidence). Scanning mateclaw's real `SkillConsolidationService`
        with an earlier version of the Go-only `.resolve(` receiver
        pattern shared onto Java wrongly read
        `workspace.resolve("SKILL.md")` as a guard and demoted a genuine
        finding (`applyGroup`'s unsanitized `umbrella_name` reaching this
        same helper). This reproduces that exact shape."""
        path = src_dir / "T.java"
        path.write_text(_java_src(
            "  private static String readWorkspaceContent(java.nio.file.Path workspace) {\n"
            "    java.nio.file.Path skillMd = workspace.resolve(\"SKILL.md\");\n"
            "    return java.nio.file.Files.readString(skillMd);\n"
            "  }"
        ), encoding="utf-8")
        f = _taint_finding("tnt-ja-ai-llmout-path-001", path, Category.PATH_TRAVERSAL,
                            sink_line=8, snippet="umbrellaName")
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH
        assert "guard_effect" not in out.metadata

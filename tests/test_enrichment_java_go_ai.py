"""BACKLOG.md JG-02: enrichment must not bury Java/Go AI findings.

The AI-context gate, the web-framework gate and the source-origin ladder
were written against Python imports and a Python AST. These tests pin the
Java/Go behaviour: a `tnt-ja-ai-*` / `tnt-go-ai-*` finding in a file with a
Java/Go AI import keeps its severity, a rule-declared `source_kind` stands in
for the AST tracer on files it cannot parse, and the ported rule ids classify
the same way their Python originals do.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity, TaintFlow, TaintNode
from rowan.core.rule_class import is_dangerous_rule, is_inventory_rule, rule_class
from rowan.passes.enrichment import (
    EnrichmentPass,
    _file_has_ai_imports,
    _file_has_web_imports,
)

SPRING_AI_JAVA = """package demo;

import org.springframework.ai.chat.client.ChatClient;
import java.sql.Statement;

public class Svc {
    String run(ChatClient client, Statement st) throws Exception {
        String sql = client.prompt().user("q").call().content();
        st.executeQuery(sql);
        return sql;
    }
}
"""

PLAIN_JAVA = SPRING_AI_JAVA.replace("import org.springframework.ai.chat.client.ChatClient;\n", "")

MCP_GO = """package main

import (
    "context"
    "os/exec"

    "github.com/mark3labs/mcp-go/mcp"
)

func handle(ctx context.Context, req mcp.CallToolRequest) {
    cmd := req.GetString("cmd", "")
    exec.Command("sh", "-c", cmd).Run()
}
"""

PLAIN_GO = MCP_GO.replace('    "github.com/mark3labs/mcp-go/mcp"\n', "")


@pytest.fixture
def src_dir(tmp_path_factory):
    """A fixture directory with no `test` in its path: pytest's `tmp_path`
    embeds the test name, which `_suppress_test_findings` treats as test
    code and demotes."""
    return tmp_path_factory.mktemp("javago")


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
    rule_id: str,
    path: Path,
    category: Category,
    *,
    severity: Severity = Severity.HIGH,
    source_line: int,
    sink_line: int,
    snippet: str,
    source_kind: str | None = None,
) -> Finding:
    metadata = {"source_kind": source_kind} if source_kind else {}
    return Finding(
        rule_id=rule_id, message="m", severity=severity, category=category,
        file_path=str(path), start_line=sink_line, engine="opengrep", confidence=0.9,
        taint_flow=TaintFlow(
            source=TaintNode(file_path=str(path), line=source_line, snippet=snippet),
            sink=TaintNode(file_path=str(path), line=sink_line),
            intermediate=[],
        ),
        metadata=metadata,
    )


class TestAiContextGate:
    def test_java_spring_ai_import_keeps_high(self, src_dir):
        path = src_dir / "Svc.java"
        path.write_text(SPRING_AI_JAVA, encoding="utf-8")
        f = _taint_finding(
            "tnt-ja-ai-llmout-sql-001", path, Category.INJECTION,
            source_line=8, sink_line=9,
            snippet='client.prompt().user("q").call().content()',
            source_kind="llm_output",
        )
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH
        assert out.confidence >= 0.7
        assert "ai_context_gate" not in out.metadata

    def test_java_without_ai_import_is_floored(self, src_dir):
        path = src_dir / "Svc.java"
        path.write_text(PLAIN_JAVA, encoding="utf-8")
        f = _taint_finding(
            "tnt-ja-ai-llmout-sql-001", path, Category.INJECTION,
            source_line=7, sink_line=8,
            snippet='client.prompt().user("q").call().content()',
            source_kind="llm_output",
        )
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.INFO
        assert out.confidence <= 0.3
        assert out.metadata.get("ai_context_gate") is True

    def test_go_mcp_import_keeps_high(self, src_dir):
        path = src_dir / "main.go"
        path.write_text(MCP_GO, encoding="utf-8")
        f = _taint_finding(
            "tnt-go-ai-mcptool-exec-001", path, Category.COMMAND_INJECTION,
            source_line=11, sink_line=12,
            snippet='req.GetString("cmd", "")',
            source_kind="tool_param",
        )
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.HIGH
        assert out.confidence >= 0.7
        assert "ai_context_gate" not in out.metadata

    def test_go_without_mcp_import_is_floored(self, src_dir):
        path = src_dir / "main.go"
        path.write_text(PLAIN_GO, encoding="utf-8")
        f = _taint_finding(
            "tnt-go-ai-mcptool-exec-001", path, Category.COMMAND_INJECTION,
            source_line=10, sink_line=11,
            snippet='req.GetString("cmd", "")',
            source_kind="tool_param",
        )
        (out,) = _run_enrichment([f])
        assert out.severity == Severity.INFO
        assert out.metadata.get("ai_context_gate") is True


class TestAiImportSyntax:
    @pytest.mark.parametrize("module", [
        "mcp",
        "fastmcp",
        "google.adk",
        "agents",
        "pydantic_ai",
        "smolagents",
        "langgraph",
        "claude_agent_sdk",
        "semantic_kernel",
        "haystack",
        "dspy",
        "letta",
        "instructor",
        "ag2",
    ])
    def test_modern_python_agent_import_counts(self, tmp_path, module):
        path = tmp_path / "agent.py"
        path.write_text(f"from {module} import Agent\n", encoding="utf-8")
        assert _file_has_ai_imports(str(path)) is True

    @pytest.mark.parametrize("line", [
        "agents = load_workers()",
        "from myapp.agents import x",
        "from agents_util import x",
        "import agentsmith",
    ])
    def test_generic_agents_name_does_not_count(self, tmp_path, line):
        """`agents` is only the OpenAI Agents SDK when it is the whole first
        segment of the import; every project with an `agents/` package
        would otherwise count as AI code."""
        path = tmp_path / "plain.py"
        path.write_text(f"import os\n{line}\n", encoding="utf-8")
        assert _file_has_ai_imports(str(path)) is False

    @pytest.mark.parametrize(("imports", "expected"), [
        ("from fastmcp import FastMCP", Severity.MEDIUM),
        ("import os", Severity.INFO),
    ])
    def test_fastmcp_import_keeps_ai_finding_at_rule_severity(self, src_dir, imports, expected):
        """TNT-ML-036 is WARNING (MEDIUM) in agent_taint.yaml. A file whose
        only AI import is `fastmcp` keeps that; the same finding on a file
        with no AI import is floored to INFO by the AI-context gate."""
        path = src_dir / "server.py"
        path.write_text(f"{imports}\n", encoding="utf-8")
        finding = Finding(
            rule_id="TNT-ML-036",
            message="tool parameter reaches MCP sampling",
            severity=Severity.MEDIUM,
            category=Category.PROMPT_INJECTION,
            file_path=str(path),
            start_line=1,
            engine="opengrep",
            confidence=0.9,
        )
        (out,) = _run_enrichment([finding])
        assert out.severity == expected
        assert ("ai_context_gate" in out.metadata) == (expected == Severity.INFO)

    @pytest.mark.parametrize("line", [
        "import org.springframework.ai.chat.client.ChatClient;",
        "import dev.langchain4j.model.chat.ChatLanguageModel;",
        "import com.openai.client.OpenAIClient;",
        "import com.anthropic.client.AnthropicClient;",
        "import io.modelcontextprotocol.client.McpClient;",
        "import ai.djl.Model;",
        "import ai.onnxruntime.OrtSession;",
        "import org.deeplearning4j.nn.api.Model;",
        "import static dev.langchain4j.data.message.UserMessage.userMessage;",
    ])
    def test_java_import_counts(self, tmp_path, line):
        path = tmp_path / "A.java"
        path.write_text(f"package a;\n\n{line}\n\npublic class A {{}}\n", encoding="utf-8")
        assert _file_has_ai_imports(str(path)) is True

    @pytest.mark.parametrize("pkg", [
        "github.com/tmc/langchaingo/llms",
        "github.com/openai/openai-go",
        "github.com/sashabaranov/go-openai",
        "github.com/anthropics/anthropic-sdk-go",
        "github.com/mark3labs/mcp-go/mcp",
        "github.com/modelcontextprotocol/go-sdk/mcp",
        "github.com/firebase/genkit/go/genkit",
        "github.com/ollama/ollama/api",
        "github.com/cloudwego/eino/compose",
    ])
    def test_go_import_block_counts(self, tmp_path, pkg):
        path = tmp_path / "a.go"
        path.write_text(f'package a\n\nimport (\n\t"fmt"\n\t"{pkg}"\n)\n', encoding="utf-8")
        assert _file_has_ai_imports(str(path)) is True

    def test_go_aliased_single_import_counts(self, tmp_path):
        path = tmp_path / "a.go"
        path.write_text('package a\n\nimport openai "github.com/sashabaranov/go-openai"\n', encoding="utf-8")
        assert _file_has_ai_imports(str(path)) is True

    @pytest.mark.parametrize("text", [
        'package a;\n// migrated from dev.langchain4j, see docs\nimport java.util.List;\n',
        'package a;\nString s = "org.springframework.ai.chat";\n',
        'package a\n\nimport "fmt"\n\nvar s = "github.com/mark3labs/mcp-go/mcp"\n',
        'package a\n\n// "github.com/tmc/langchaingo/llms"\nimport "fmt"\n',
    ])
    def test_mention_outside_import_does_not_count(self, tmp_path, text):
        path = tmp_path / ("a.go" if text.startswith("package a\n") else "A.java")
        path.write_text(text, encoding="utf-8")
        assert _file_has_ai_imports(str(path)) is False


class TestWebFrameworkGate:
    @pytest.mark.parametrize("text", [
        "package a;\nimport jakarta.ws.rs.GET;\n",
        "package a;\nimport javax.ws.rs.Path;\n",
        "package a;\nimport jakarta.servlet.http.HttpServletRequest;\n",
        "package a;\nimport io.javalin.Javalin;\n",
        "package a;\nimport io.ktor.server.application.*;\n",
    ])
    def test_java_web_imports_count(self, tmp_path, text):
        path = tmp_path / "A.java"
        path.write_text(text, encoding="utf-8")
        assert _file_has_web_imports(str(path)) is True

    def test_go_chi_counts(self, tmp_path):
        path = tmp_path / "a.go"
        path.write_text('package a\n\nimport (\n\t"net/url"\n\t"github.com/go-chi/chi/v5"\n)\n', encoding="utf-8")
        assert _file_has_web_imports(str(path)) is True

    def test_jaxrs_xss_finding_passes_gate(self, tmp_path):
        path = tmp_path / "Res.java"
        path.write_text(
            "package a;\n\nimport jakarta.ws.rs.GET;\n\npublic class Res {}\n",
            encoding="utf-8",
        )
        f = Finding(
            rule_id="tnt-ja-ai-llmout-xss-001", message="xss", severity=Severity.HIGH,
            category=Category.XSS, file_path=str(path), start_line=5,
            engine="opengrep", confidence=0.9,
        )
        (out,) = EnrichmentPass()._suppress_web_rules_on_non_web_files([f])
        assert out.severity == Severity.HIGH
        assert "web_context_gate" not in out.metadata


class TestSourceKindOrigin:
    def test_llm_output_floors_dangerous_sink_to_high(self, src_dir):
        path = src_dir / "Svc.java"
        path.write_text(SPRING_AI_JAVA, encoding="utf-8")
        f = _taint_finding(
            "tnt-ja-ai-llmout-sql-001", path, Category.INJECTION,
            severity=Severity.MEDIUM, source_line=8, sink_line=9,
            snippet="sql", source_kind="llm_output",
        )
        (out,) = _run_enrichment([f])
        assert out.metadata["source_origin"] == "llm_output"
        assert out.metadata["source_confidence"] == 0.95
        assert out.severity == Severity.HIGH
        assert out.metadata["severity_floor_applied"] == "dangerous_sink_with_taint_flow"

    def test_config_is_demoted_like_python(self, src_dir):
        path = src_dir / "Svc.java"
        path.write_text(SPRING_AI_JAVA, encoding="utf-8")
        f = _taint_finding(
            "tnt-ja-ai-toolexec-001", path, Category.COMMAND_INJECTION,
            source_line=8, sink_line=9, snippet="cmd", source_kind="config",
        )
        (out,) = _run_enrichment([f])
        assert out.metadata["source_origin"] == "config_constant"
        assert out.metadata["source_confidence"] == 0.4
        assert out.severity == Severity.INFO
        assert out.metadata["taint_unconfirmed"] is True

    def test_http_input_resolves_with_full_confidence(self, src_dir):
        path = src_dir / "Svc.java"
        path.write_text(SPRING_AI_JAVA, encoding="utf-8")
        f = _taint_finding(
            "tnt-ja-ai-sqli-001", path, Category.INJECTION,
            source_line=8, sink_line=9, snippet="q", source_kind="http_input",
        )
        (out,) = _run_enrichment([f])
        assert out.metadata["source_origin"] == "http_input"
        assert out.metadata["source_confidence"] == 1.0
        assert out.severity == Severity.HIGH


class TestRuleClass:
    @pytest.mark.parametrize("rule_id", [
        "tnt-ja-ai-sysprompt-001",
        "tnt-ja-ai-vectorq-001",
        "tnt-go-ai-mcpbind-001",
        "tnt-go-ai-sysprompt-001",
    ])
    def test_surface_signals_are_inventory(self, rule_id):
        assert is_inventory_rule(rule_id) is True
        assert rule_class(rule_id) == "inventory"

    @pytest.mark.parametrize("rule_id", [
        "tnt-ja-ai-llmout-sql-001",
        "tnt-ja-ai-llmout-exec-001",
        "tnt-ja-ai-toolexec-001",
        "tnt-ja-ai-mcpcmd-001",
        "tnt-ja-ai-yaml-001",
        "tnt-ja-ai-llmout-spel-001",
        "tnt-go-ai-mcptool-exec-001",
        "tnt-go-ai-llmout-ssrf-001",
    ])
    def test_dangerous_classes_are_vulnerabilities(self, rule_id):
        # Same as the Python originals (TNT-AIML-*, TNT-ML-*): the category
        # carries the dangerous-sink decision, rule_class only rules out inventory.
        assert is_inventory_rule(rule_id) is False
        assert rule_class(rule_id) == "vulnerability"
        assert is_dangerous_rule(rule_id) is is_dangerous_rule("TNT-AIML-001")

"""BACKLOG.md JG-05 / JG-06: Java LLM-output and request-to-prompt/MCP rules.

`rules/java_llm_taint.yaml` carries eleven taint rules: the seven
`tnt-ja-ai-llmout-{sql,exec,ssrf,path,xss,spel,deser}-001` rules (LLM
completion text reaches a dangerous sink), `tnt-ja-ai-sysprompt-001` (a
request value reaches the system prompt or a prompt template),
`tnt-ja-ai-mcpcmd-001` (a request/env value reaches an MCP stdio
command/args or transport URL), `tnt-ja-ai-yaml-001` (a request value
reaches an unsafe SnakeYAML load) and `tnt-ja-ai-vectorq-001` (a request
value reaches a vector-store filter or a Neo4j Cypher query).
`rules/java_llm_opengrep.yaml` carries the search-mode companion
`tnt-ja-ai-mcpcmd-002` (a non-literal MCP command/builder argument, the
aideepin DB-row shape a taint rule in the same file cannot see).

Each rule gets at least one true positive and one true negative (a constant
value into the sink). Requires the Opengrep binary (skipped entirely if not
installed, matching the project's convention).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from rowan.analysis.test_paths import is_test_path
from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline
from rowan.reporters import to_json
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
TAINT_RULES = "java_llm_taint.yaml"
SEARCH_RULES = "java_llm_opengrep.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

SPRING_AI_CHAT_CLIENT = "import org.springframework.ai.chat.client.ChatClient;\n"


def _scan(tmp_path, filename, rule_file, source, rule_id, language):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=[language])
    return [f for f in findings if f.rule_id == rule_id]


def _java(imports: str, body: str, cls: str = "Svc") -> str:
    return f"{imports}\npublic class {cls} {{\n{body}\n}}\n"


class TestLlmOutputSql:
    RULE = "tnt-ja-ai-llmout-sql-001"

    def test_spring_ai_content_into_statement(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import java.sql.Connection;\nimport java.sql.Statement;\n",
            "    private ChatClient chatClient;\n"
            "    private Connection conn;\n"
            "    public void ask(String q) throws Exception {\n"
            '        String sql = chatClient.prompt().user(q).call().content();\n'
            "        Statement st = conn.createStatement();\n"
            "        st.executeQuery(sql);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_spring_ai_content_into_jdbc_template_sql_text(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.springframework.jdbc.core.JdbcTemplate;\n",
            "    private ChatClient chatClient;\n"
            "    private JdbcTemplate jdbcTemplate;\n"
            "    public void ask(String q) {\n"
            '        String sql = chatClient.prompt().user(q).call().content();\n'
            "        jdbcTemplate.queryForList(sql);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_jdbc_template_bound_argument_is_quiet(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.springframework.jdbc.core.JdbcTemplate;\n",
            "    private ChatClient chatClient;\n"
            "    private JdbcTemplate jdbcTemplate;\n"
            "    public void ask(String q) {\n"
            '        String name = chatClient.prompt().user(q).call().content();\n'
            '        jdbcTemplate.queryForList("SELECT * FROM t WHERE name = ?", name);\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits

    def test_langchain4j_chat_into_jdbc_statement(self, tmp_path):
        src = _java(
            "import dev.langchain4j.model.chat.ChatLanguageModel;\n"
            "import java.sql.Connection;\nimport java.sql.Statement;\n",
            "    private ChatLanguageModel model;\n"
            "    private Connection conn;\n"
            "    public void ask() throws Exception {\n"
            '        String sql = model.chat("hi");\n'
            "        Statement st = conn.createStatement();\n"
            "        st.executeQuery(sql);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_sql_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import java.sql.Connection;\nimport java.sql.Statement;\n",
            "    private ChatClient chatClient;\n"
            "    private Connection conn;\n"
            "    public void ask(String q) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            "        Statement st = conn.createStatement();\n"
            '        st.executeQuery("SELECT 1");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestLlmOutputExec:
    RULE = "tnt-ja-ai-llmout-exec-001"

    def test_spring_ai_content_into_process_builder(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT,
            "    private ChatClient chatClient;\n"
            "    public void run(String q) throws Exception {\n"
            '        String cmd = chatClient.prompt().user(q).call().content();\n'
            '        new ProcessBuilder("sh", "-c", cmd).start();\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_command_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT,
            "    private ChatClient chatClient;\n"
            "    public void run(String q) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            '        new ProcessBuilder("ls", "-la").start();\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestLlmOutputSsrf:
    RULE = "tnt-ja-ai-llmout-ssrf-001"

    def test_spring_ai_content_into_rest_template(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.springframework.web.client.RestTemplate;\n",
            "    private ChatClient chatClient;\n"
            "    private RestTemplate restTemplate;\n"
            "    public String fetch(String q) throws Exception {\n"
            '        String url = chatClient.prompt().user(q).call().content();\n'
            "        return restTemplate.getForObject(url, String.class);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_url_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.springframework.web.client.RestTemplate;\n",
            "    private ChatClient chatClient;\n"
            "    private RestTemplate restTemplate;\n"
            "    public String fetch(String q) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            '        return restTemplate.getForObject("https://api.example.com", String.class);\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestLlmOutputPath:
    RULE = "tnt-ja-ai-llmout-path-001"

    def test_spring_ai_content_into_new_file(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import java.io.File;\n",
            "    private ChatClient chatClient;\n"
            "    public void read(String q) throws Exception {\n"
            '        String name = chatClient.prompt().user(q).call().content();\n'
            "        new File(name);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_path_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT,
            "    private ChatClient chatClient;\n"
            "    public void read(String q) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            '        new java.io.File("/srv/data/report.txt");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestLlmOutputXss:
    RULE = "tnt-ja-ai-llmout-xss-001"

    def test_spring_ai_content_into_response_writer(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import javax.servlet.http.HttpServletResponse;\n",
            "    private ChatClient chatClient;\n"
            "    public void render(String q, HttpServletResponse resp) throws Exception {\n"
            '        String html = chatClient.prompt().user(q).call().content();\n'
            "        resp.getWriter().println(html);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_body_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import javax.servlet.http.HttpServletResponse;\n",
            "    private ChatClient chatClient;\n"
            "    public void render(String q, HttpServletResponse resp) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            '        resp.getWriter().println("ok");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestLlmOutputSpel:
    RULE = "tnt-ja-ai-llmout-spel-001"

    def test_spring_ai_content_into_spel_parser(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.springframework.expression.spel.standard.SpelExpressionParser;\n",
            "    private ChatClient chatClient;\n"
            "    private SpelExpressionParser parser;\n"
            "    public void run(String q) throws Exception {\n"
            '        String expr = chatClient.prompt().user(q).call().content();\n'
            "        parser.parseExpression(expr);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_expression_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.springframework.expression.spel.standard.SpelExpressionParser;\n",
            "    private ChatClient chatClient;\n"
            "    private SpelExpressionParser parser;\n"
            "    public void run(String q) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            '        parser.parseExpression("1 + 1");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestLlmOutputDeser:
    RULE = "tnt-ja-ai-llmout-deser-001"

    def test_spring_ai_content_into_yaml_load(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.yaml.snakeyaml.Yaml;\n",
            "    private ChatClient chatClient;\n"
            "    public void run(String q) throws Exception {\n"
            '        String body = chatClient.prompt().user(q).call().content();\n'
            "        new Yaml().load(body);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_constant_yaml_is_clean(self, tmp_path):
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import org.yaml.snakeyaml.Yaml;\n",
            "    private ChatClient chatClient;\n"
            "    public void run(String q) throws Exception {\n"
            '        String note = chatClient.prompt().user(q).call().content();\n'
            '        new Yaml().load("a: 1");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestSysPrompt:
    RULE = "tnt-ja-ai-sysprompt-001"

    def test_request_param_into_system_message(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.springframework.ai.chat.messages.SystemMessage;\n",
            "    public void configure(@RequestParam String persona) {\n"
            "        new SystemMessage(persona);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_literal_system_message_is_clean(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.springframework.ai.chat.messages.SystemMessage;\n",
            "    public void configure(@RequestParam String topic) {\n"
            '        new SystemMessage("You are a helpful assistant.");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestMcpCmdTaint:
    RULE = "tnt-ja-ai-mcpcmd-001"

    def test_request_param_into_stdio_command(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.springframework.ai.mcp.client.transport.StdioMcpTransport;\n",
            "    public void connect(@RequestParam String cmd, StdioMcpTransport transport) {\n"
            "        transport.command(cmd);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_literal_command_is_clean(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.springframework.ai.mcp.client.transport.StdioMcpTransport;\n",
            "    public void connect(@RequestParam String label, StdioMcpTransport transport) {\n"
            '        transport.command("mcp-server");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestYaml:
    RULE = "tnt-ja-ai-yaml-001"

    def test_request_param_into_unsafe_yaml_load(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.yaml.snakeyaml.Yaml;\n",
            "    public void load(@RequestParam String body) {\n"
            "        Yaml yaml = new Yaml();\n"
            "        yaml.load(body);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_properties_load_is_not_a_yaml_sink(self, tmp_path):
        """apache/dubbo: `Properties.load(...)` matched the untyped `$Y.load`."""
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import java.io.StringReader;\nimport java.util.Properties;\n",
            "    public void load(@RequestParam String body) throws Exception {\n"
            "        Properties props = new Properties();\n"
            "        props.load(new StringReader(body));\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits

    def test_safe_constructor_is_clean(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.yaml.snakeyaml.Yaml;\n"
            "import org.yaml.snakeyaml.constructor.SafeConstructor;\n",
            "    public void load(@RequestParam String body) {\n"
            "        Yaml yaml = new Yaml(new SafeConstructor());\n"
            "        yaml.load(body);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits


class TestVectorq:
    RULE = "tnt-ja-ai-vectorq-001"

    def test_request_param_into_neo4j_session_run(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.neo4j.driver.Session;\n",
            "    public void run(@RequestParam String cypher, Session session) {\n"
            "        session.run(cypher);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_literal_cypher_is_clean(self, tmp_path):
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import org.neo4j.driver.Session;\n",
            "    public void run(@RequestParam String label, Session session) {\n"
            '        session.run("MATCH (n) RETURN n LIMIT 1");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not hits, hits

    def test_generic_sqli_rule_not_duplicated_by_vectorq(self, tmp_path):
        """The aideepin ApacheAgeGraphStore shape (.formatted() Cypher through
        Statement.executeQuery) must fire tnt-ja-sqli-001 only, not vectorq
        too: vectorq deliberately excludes the Statement.executeQuery sink to
        avoid double-reporting the identical flow."""
        src = _java(
            "import org.springframework.web.bind.annotation.RequestParam;\n"
            "import java.sql.Connection;\nimport java.sql.Statement;\n",
            "    public void run(@RequestParam String label, Connection conn) throws Exception {\n"
            '        String cypher = "MATCH (n {name: \'%s\'}) RETURN n".formatted(label);\n'
            "        Statement st = conn.createStatement();\n"
            "        st.executeQuery(cypher);\n"
            "    }",
        )
        vectorq_hits = _scan(tmp_path, "Svc.java", TAINT_RULES, src, self.RULE, "java")
        assert not vectorq_hits, vectorq_hits
        sqli_hits = _scan(tmp_path, "Svc.java", "java_taint.yaml", src, "tnt-ja-sqli-001", "java")
        assert len(sqli_hits) == 1, sqli_hits


class TestMcpCmdSearch:
    RULE = "tnt-ja-ai-mcpcmd-002"

    def test_db_row_command_is_non_literal(self, tmp_path):
        """The aideepin UserMcpService shape: the command is a getter on a DB
        entity in the same statement, not a string literal."""
        src = _java(
            "import org.springframework.ai.mcp.client.transport.StdioMcpTransport;\n",
            "    public void connect(StdioMcpTransport transport, McpServerEntity entity) {\n"
            "        transport.command(entity.getStdioCommand());\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", SEARCH_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits

    def test_literal_command_is_clean(self, tmp_path):
        src = _java(
            "import org.springframework.ai.mcp.client.transport.StdioMcpTransport;\n",
            "    public void connect(StdioMcpTransport transport) {\n"
            '        transport.command("mcp-server");\n'
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", SEARCH_RULES, src, self.RULE, "java")
        assert not hits, hits

    def test_server_parameters_builder_non_literal(self, tmp_path):
        src = _java(
            "import io.modelcontextprotocol.client.transport.ServerParameters;\n",
            "    public void connect(McpServerEntity entity) {\n"
            "        ServerParameters.builder(entity.getStdioCommand());\n"
            "    }",
        )
        hits = _scan(tmp_path, "Svc.java", SEARCH_RULES, src, self.RULE, "java")
        assert len(hits) == 1, hits


class TestFullScanLlmOutputSqlOrigin:
    def test_full_scan_keeps_high_with_llm_origin(self):
        """Enrichment has no Java AST: the `source_kind: llm_output` metadata
        must still give the finding an LLM-derived origin and keep it HIGH.

        Scans a plain temp dir rather than pytest's tmp_path: that path
        contains the test function name, and the test-path demotion would cap
        the finding at MEDIUM before this assertion could see it.
        """
        src = _java(
            SPRING_AI_CHAT_CLIENT + "import java.sql.Connection;\nimport java.sql.Statement;\n",
            "    private ChatClient chatClient;\n"
            "    private Connection conn;\n"
            "    public void ask(String q) throws Exception {\n"
            '        String sql = chatClient.prompt().user(q).call().content();\n'
            "        Statement st = conn.createStatement();\n"
            "        st.executeQuery(sql);\n"
            "    }",
        )
        with tempfile.TemporaryDirectory(prefix="rowan-java-llm-") as tmp:
            target = Path(tmp)
            assert not is_test_path(str(target / "Svc.java"))
            (target / "Svc.java").write_text(src, encoding="utf-8")
            config = ScanConfig(target=target, no_sca=True, languages=["java"])
            result = ScanPipeline(config).run()

        hits = [f for f in result.findings if f.rule_id == "tnt-ja-ai-llmout-sql-001"]
        assert len(hits) == 1, [f.rule_id for f in result.findings]
        assert hits[0].metadata.get("source_origin") == "llm_output"
        assert hits[0].metadata.get("source_confidence") == 0.95

        report = json.loads(to_json(result))
        (row,) = [f for f in report["findings"] if f["rule_id"] == "tnt-ja-ai-llmout-sql-001"]
        assert row["severity"] == "high"
        assert row["confidence"] >= 0.7

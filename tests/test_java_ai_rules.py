"""Java AI-surface taint rules (rules/java_ai_taint.yaml, JG-04).

A Spring AI / LangChain4j ``@Tool`` method's parameters are chosen by the
model, so whoever controls the prompt controls them. These tests pin each
``tnt-ja-ai-tool*-001`` rule with a Spring AI TP, a LangChain4j TP, and a TN
where the sink argument is a constant and the tool parameter goes elsewhere.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention; CI does not install it).
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
RULE_FILE = "java_ai_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

SPRING_TOOL = "import org.springframework.ai.tool.annotation.Tool;\n"
SPRING_TOOL_PARAM = "import org.springframework.ai.tool.annotation.ToolParam;\n"
LC4J_TOOL = "import dev.langchain4j.agent.tool.Tool;\nimport dev.langchain4j.agent.tool.P;\n"


def _scan(tmp_path, filename, rule_file, source, rule_id, language):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=[language])
    return [f for f in findings if f.rule_id == rule_id]


def _java(imports: str, body: str, cls: str = "Tools") -> str:
    return f"{imports}\npublic class {cls} {{\n{body}\n}}\n"


class TestJavaToolParamRules:
    # ---- tnt-ja-ai-toolexec-001 -------------------------------------------

    def test_toolexec_spring_ai_process_builder(self, tmp_path):
        src = _java(
            SPRING_TOOL,
            '    @Tool(description = "Run a shell command")\n'
            "    public String run(String command) throws Exception {\n"
            '        new ProcessBuilder("sh", "-c", command).start();\n'
            '        return "ok";\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolexec-001", "java")
        assert len(hits) == 1, hits

    def test_toolexec_langchain4j_runtime_exec(self, tmp_path):
        src = _java(
            LC4J_TOOL,
            '    @Tool("Run a shell command")\n'
            '    public String run(@P("the command") String command) throws Exception {\n'
            "        Runtime.getRuntime().exec(command);\n"
            '        return "ok";\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolexec-001", "java")
        assert len(hits) == 1, hits

    def test_toolexec_constant_command_is_clean(self, tmp_path):
        src = _java(
            SPRING_TOOL,
            '    @Tool(description = "List the workspace")\n'
            "    public String run(String label) throws Exception {\n"
            '        new ProcessBuilder("ls", "-la", "/srv/workspace").start();\n'
            '        return "listed for " + label;\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolexec-001", "java")
        assert not hits, hits

    # ---- tnt-ja-ai-toolpath-001 -------------------------------------------

    def test_toolpath_spring_ai_files_read_string(self, tmp_path):
        src = _java(
            SPRING_TOOL + SPRING_TOOL_PARAM + "import java.nio.file.Files;\nimport java.nio.file.Paths;\n",
            '    @Tool(description = "Read a file")\n'
            '    public String read(@ToolParam(description = "file name") String fileName) throws Exception {\n'
            '        return Files.readString(Paths.get("/data/" + fileName));\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolpath-001", "java")
        assert hits, "expected the tool parameter to reach Paths.get / Files.readString"

    def test_toolpath_langchain4j_new_file(self, tmp_path):
        src = _java(
            LC4J_TOOL + "import java.io.File;\n",
            '    @Tool("Delete a file")\n'
            "    public boolean delete(String path) {\n"
            "        return new File(path).delete();\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolpath-001", "java")
        assert len(hits) == 1, hits

    def test_toolpath_constant_path_is_clean(self, tmp_path):
        src = _java(
            SPRING_TOOL + "import java.nio.file.Files;\nimport java.nio.file.Paths;\n",
            '    @Tool(description = "Append a note")\n'
            "    public String note(String text) throws Exception {\n"
            '        Files.writeString(Paths.get("/data/notes.txt"), text);\n'
            '        return "ok";\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolpath-001", "java")
        assert not hits, hits

    # ---- tnt-ja-ai-toolsql-001 --------------------------------------------

    def test_toolsql_spring_ai_jdbc_template_concat(self, tmp_path):
        src = _java(
            SPRING_TOOL + "import org.springframework.jdbc.core.JdbcTemplate;\nimport java.util.List;\nimport java.util.Map;\n",
            "    private JdbcTemplate jdbcTemplate;\n"
            '    @Tool(description = "Find a customer")\n'
            "    public List<Map<String, Object>> find(String name) {\n"
            "        return jdbcTemplate.queryForList(\"SELECT * FROM customers WHERE name = '\" + name + \"'\");\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolsql-001", "java")
        assert len(hits) == 1, hits

    def test_toolsql_langchain4j_statement(self, tmp_path):
        src = _java(
            LC4J_TOOL + "import java.sql.Connection;\nimport java.sql.Statement;\n",
            "    private Connection conn;\n"
            '    @Tool("Run a query")\n'
            "    public String query(String sql) throws Exception {\n"
            "        Statement st = conn.createStatement();\n"
            "        st.executeQuery(sql);\n"
            '        return "ok";\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolsql-001", "java")
        assert len(hits) == 1, hits

    def test_toolsql_parameterised_jdbc_template_is_clean(self, tmp_path):
        """Constant SQL with the tool parameter bound through args must not fire."""
        src = _java(
            SPRING_TOOL + "import org.springframework.jdbc.core.JdbcTemplate;\nimport java.util.List;\nimport java.util.Map;\n",
            "    private JdbcTemplate jdbcTemplate;\n"
            '    @Tool(description = "Find a customer")\n'
            "    public List<Map<String, Object>> find(String name) {\n"
            '        String sql = "SELECT * FROM customers WHERE name = ?";\n'
            "        return jdbcTemplate.queryForList(sql, name);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolsql-001", "java")
        assert not hits, hits

    def test_toolsql_constant_query_is_clean(self, tmp_path):
        src = _java(
            SPRING_TOOL + "import org.springframework.jdbc.core.JdbcTemplate;\n",
            "    private JdbcTemplate jdbcTemplate;\n"
            '    @Tool(description = "Count customers")\n'
            "    public String count(String label) {\n"
            '        Integer n = jdbcTemplate.queryForObject("SELECT COUNT(*) FROM customers", Integer.class);\n'
            '        return label + ": " + n;\n'
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolsql-001", "java")
        assert not hits, hits

    # ---- tnt-ja-ai-toolssrf-001 -------------------------------------------

    def test_toolssrf_spring_ai_jsoup(self, tmp_path):
        src = _java(
            SPRING_TOOL + "import org.jsoup.Jsoup;\n",
            '    @Tool(description = "Scrape a page")\n'
            "    public String scrape(String url) throws Exception {\n"
            "        return Jsoup.connect(url).get().html();\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolssrf-001", "java")
        assert len(hits) == 1, hits

    def test_toolssrf_langchain4j_rest_template(self, tmp_path):
        src = _java(
            LC4J_TOOL + "import org.springframework.web.client.RestTemplate;\n",
            "    private RestTemplate restTemplate;\n"
            '    @Tool("Fetch a URL")\n'
            "    public String fetch(String url) {\n"
            "        return restTemplate.getForObject(url, String.class);\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolssrf-001", "java")
        assert len(hits) == 1, hits

    def test_toolssrf_http_client_uri_create(self, tmp_path):
        src = _java(
            SPRING_TOOL
            + "import java.net.URI;\nimport java.net.http.HttpClient;\nimport java.net.http.HttpRequest;\nimport java.net.http.HttpResponse;\n",
            "    private HttpClient client;\n"
            '    @Tool(description = "Fetch a URL")\n'
            "    public String fetch(String url) throws Exception {\n"
            "        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).build();\n"
            "        return client.send(req, HttpResponse.BodyHandlers.ofString()).body();\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolssrf-001", "java")
        assert hits, "expected the tool parameter to reach URI.create / HttpRequest.newBuilder"

    def test_toolssrf_constant_url_is_clean(self, tmp_path):
        src = _java(
            SPRING_TOOL + "import org.springframework.web.client.RestTemplate;\n",
            "    private RestTemplate restTemplate;\n"
            '    @Tool(description = "Weather")\n'
            "    public String weather(String city) {\n"
            '        String body = restTemplate.getForObject("https://api.example.com/weather", String.class);\n'
            "        return city + body;\n"
            "    }",
        )
        hits = _scan(tmp_path, "Tools.java", RULE_FILE, src, "tnt-ja-ai-toolssrf-001", "java")
        assert not hits, hits

    # ---- no AI surface, no rule ---------------------------------------------

    def test_plain_method_parameter_is_not_a_source(self, tmp_path):
        src = _java(
            "",
            "    public String run(String command) throws Exception {\n"
            '        new ProcessBuilder("sh", "-c", command).start();\n'
            '        return "ok";\n'
            "    }",
        )
        for rule_id in (
            "tnt-ja-ai-toolexec-001",
            "tnt-ja-ai-toolpath-001",
            "tnt-ja-ai-toolsql-001",
            "tnt-ja-ai-toolssrf-001",
        ):
            assert not _scan(tmp_path, "Tools.java", RULE_FILE, src, rule_id, "java")


class TestJavaToolParamEnrichment:
    def test_full_scan_keeps_high_with_llm_origin(self):
        """Enrichment has no Java AST: the `source_kind: tool_param` metadata must
        still give the finding an LLM-derived origin and keep it HIGH.

        Scans a plain temp dir rather than pytest's tmp_path: that path contains
        the test function name, and the test-path demotion would cap the
        finding at MEDIUM before this assertion could see it.
        """
        src = _java(
            SPRING_TOOL,
            '    @Tool(description = "Run a shell command")\n'
            "    public String run(String command) throws Exception {\n"
            '        new ProcessBuilder("sh", "-c", command).start();\n'
            '        return "ok";\n'
            "    }",
        )
        with tempfile.TemporaryDirectory(prefix="rowan-java-ai-") as tmp:
            target = Path(tmp)
            assert not is_test_path(str(target / "Tools.java"))
            (target / "Tools.java").write_text(src, encoding="utf-8")
            config = ScanConfig(target=target, no_sca=True, languages=["java"])
            result = ScanPipeline(config).run()

        hits = [f for f in result.findings if f.rule_id == "tnt-ja-ai-toolexec-001"]
        assert len(hits) == 1, [f.rule_id for f in result.findings]
        assert hits[0].metadata.get("source_origin") == "llm_output"
        assert hits[0].metadata.get("source_confidence") == 0.95
        assert "ai_context_gate" not in hits[0].metadata

        report = json.loads(to_json(result))
        (row,) = [f for f in report["findings"] if f["rule_id"] == "tnt-ja-ai-toolexec-001"]
        assert row["severity"] == "high"
        assert row["confidence"] >= 0.7

    def test_tools_package_is_not_operator_tooling(self):
        """Spring AI apps keep @Tool classes under `tools/` (yu-ai-agent). The
        no-attacker-context cap must not treat that as operator tooling: the
        model is the caller."""
        src = _java(
            SPRING_TOOL,
            '    @Tool(description = "Run a shell command")\n'
            "    public String run(String command) throws Exception {\n"
            '        new ProcessBuilder("sh", "-c", command).start();\n'
            '        return "ok";\n'
            "    }",
        )
        with tempfile.TemporaryDirectory(prefix="rowan-java-ai-") as tmp:
            target = Path(tmp)
            tools = target / "src" / "main" / "java" / "app" / "tools"
            tools.mkdir(parents=True)
            (tools / "Tools.java").write_text(src, encoding="utf-8")
            config = ScanConfig(target=target, no_sca=True, languages=["java"])
            result = ScanPipeline(config).run()

        (hit,) = [f for f in result.findings if f.rule_id == "tnt-ja-ai-toolexec-001"]
        assert "no_attacker_context" not in hit.metadata
        assert hit.severity.value == "high"

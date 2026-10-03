"""Focused TP/TN tests for the JG-07 Java AI surface rules."""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULE_FILE = Path(__file__).parent.parent / "rules" / "java_ai_surface.yaml"


def _hits(tmp_path: Path, source: str, rule_id: str):
    target = tmp_path / "Surface.java"
    target.write_text(source, encoding="utf-8")
    rule = next(rule for rule in load_neuroscan_rules(RULE_FILE) if rule.metadata.id == rule_id)
    return rule.check(target)


def test_mcp_http_all_interfaces_fires_and_loopback_is_quiet(tmp_path):
    assert _hits(
        tmp_path,
        'provider.serverAddress("0.0.0.0");\n',
        "ns-aiml-169",
    )
    assert not _hits(
        tmp_path,
        'provider.serverAddress("127.0.0.1");\n',
        "ns-aiml-169",
    )


def test_literal_ai_api_key_fires_and_environment_lookup_is_quiet(tmp_path):
    assert _hits(
        tmp_path,
        'OpenAiApi.builder().apiKey("sk-live-1234567890abcdef").build();\n',
        "ns-aiml-170",
    )
    assert not _hits(
        tmp_path,
        'OpenAiApi.builder().apiKey(System.getenv("OPENAI_API_KEY")).build();\n',
        "ns-aiml-170",
    )


def test_nonliteral_tool_description_fires_and_literal_is_quiet(tmp_path):
    assert _hits(
        tmp_path,
        "ToolSpecification.builder().description(configuredDescription).build();\n",
        "ns-aiml-171",
    )
    assert not _hits(
        tmp_path,
        'ToolSpecification.builder().description("Read a reviewed file").build();\n',
        "ns-aiml-171",
    )


def test_djl_remote_model_url_fires_and_local_path_is_quiet(tmp_path):
    assert _hits(
        tmp_path,
        'Criteria.builder().optModelUrls("https://models.example/model.zip");\n',
        "ns-aiml-172",
    )
    assert not _hits(
        tmp_path,
        'Criteria.builder().optModelPath(Paths.get("/opt/models/reviewed"));\n',
        "ns-aiml-172",
    )


def test_nonliteral_model_load_path_fires_and_literal_is_quiet(tmp_path):
    assert _hits(tmp_path, "Model.load(userPath);\n", "ns-aiml-173")
    assert not _hits(tmp_path, 'Model.load("/opt/models/reviewed");\n', "ns-aiml-173")


def test_all_surface_rules_are_java_only():
    rules = load_neuroscan_rules(RULE_FILE)
    assert len(rules) == 5
    assert all(rule.metadata.languages == ["java"] for rule in rules)

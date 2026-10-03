"""Behavioral tests for issue #142 (model-serving infrastructure exposures):
ns-aiml-100..106 (rules/ai_security.yaml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id: str):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    matches = [r for r in rules if r.metadata.id == rule_id]
    if not matches:
        pytest.fail(f"{rule_id} not found")
    return matches[0]


class TestOllamaExposure:
    """ns-aiml-100."""

    def test_ollama_host_env_var_is_flagged(self, tmp_path):
        f = tmp_path / "run.py"
        f.write_text('OLLAMA_HOST="0.0.0.0"\n')
        assert len(_rule("ns-aiml-100").check(f)) >= 1

    def test_compose_explicit_all_interfaces_is_flagged(self, tmp_path):
        f = tmp_path / "compose.yaml"
        f.write_text(
            "services:\n  ollama:\n    ports:\n      - \"0.0.0.0:11434:11434\"\n"
        )
        assert len(_rule("ns-aiml-100").check(f)) >= 1

    def test_compose_bare_port_mapping_is_flagged(self, tmp_path):
        """Docker's default bind for a bare "host:container" port mapping
        (no explicit host IP) is 0.0.0.0 -- this is a real exposure, not a
        false positive."""
        f = tmp_path / "compose.yaml"
        f.write_text("services:\n  ollama:\n    ports:\n      - \"11434:11434\"\n")
        assert len(_rule("ns-aiml-100").check(f)) >= 1

    def test_proxy_in_same_compose_file_suppresses_finding(self, tmp_path):
        f = tmp_path / "compose.yaml"
        f.write_text(
            "services:\n"
            "  nginx:\n"
            "    image: nginx\n"
            "  ollama:\n"
            "    ports:\n"
            "      - \"0.0.0.0:11434:11434\"\n"
        )
        assert _rule("ns-aiml-100").check(f) == []

    def test_no_exposure_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("OLLAMA_HOST=\"127.0.0.1\"\n")
        assert _rule("ns-aiml-100").check(f) == []


class TestTorchServeExposure:
    """ns-aiml-101."""

    def test_management_address_public_is_flagged(self, tmp_path):
        f = tmp_path / "start.py"
        f.write_text("torchserve --start --management-address=http://0.0.0.0:8081\n")
        assert len(_rule("ns-aiml-101").check(f)) >= 1

    def test_localhost_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("torchserve --start --management-address=http://127.0.0.1:8081\n")
        assert _rule("ns-aiml-101").check(f) == []


class TestTritonExposure:
    """ns-aiml-102."""

    def test_explicit_control_mode_public_bind_is_flagged(self, tmp_path):
        f = tmp_path / "start.py"
        f.write_text("tritonserver --model-control-mode=explicit --http-address=0.0.0.0\n")
        assert len(_rule("ns-aiml-102").check(f)) >= 1

    def test_localhost_bind_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("tritonserver --model-control-mode=explicit --http-address=127.0.0.1\n")
        assert _rule("ns-aiml-102").check(f) == []


class TestBentoMLExposure:
    """ns-aiml-103."""

    def test_serve_public_host_is_flagged(self, tmp_path):
        f = tmp_path / "start.py"
        f.write_text("bentoml serve my_service:svc --host 0.0.0.0\n")
        assert len(_rule("ns-aiml-103").check(f)) >= 1

    def test_default_serve_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("bentoml serve my_service:svc\n")
        assert _rule("ns-aiml-103").check(f) == []


class TestLlamaCppExposure:
    """ns-aiml-104."""

    def test_public_bind_no_api_key_is_flagged(self, tmp_path):
        f = tmp_path / "start.py"
        f.write_text("./llama-server --host 0.0.0.0 --port 8080\n")
        assert len(_rule("ns-aiml-104").check(f)) >= 1

    def test_public_bind_with_api_key_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("./llama-server --host 0.0.0.0 --port 8080 --api-key mysecret\n")
        assert _rule("ns-aiml-104").check(f) == []


class TestVLLMServerExposure:
    """ns-aiml-105."""

    def test_public_bind_no_api_key_is_flagged(self, tmp_path):
        f = tmp_path / "start.py"
        f.write_text("vllm serve meta-llama/Llama-3 --host 0.0.0.0\n")
        assert len(_rule("ns-aiml-105").check(f)) >= 1

    def test_public_bind_with_api_key_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("vllm serve meta-llama/Llama-3 --host 0.0.0.0 --api-key mysecret\n")
        assert _rule("ns-aiml-105").check(f) == []


class TestJupyterExposure:
    """ns-aiml-106."""

    def test_empty_token_is_flagged(self, tmp_path):
        f = tmp_path / "start.py"
        f.write_text("jupyter lab --ip=0.0.0.0 --NotebookApp.token=''\n")
        assert len(_rule("ns-aiml-106").check(f)) >= 1

    def test_compose_public_port_is_flagged(self, tmp_path):
        f = tmp_path / "compose.yaml"
        f.write_text("services:\n  jupyter:\n    ports:\n      - \"0.0.0.0:8888:8888\"\n")
        assert len(_rule("ns-aiml-106").check(f)) >= 1

    def test_token_set_not_flagged(self, tmp_path):
        f = tmp_path / "clean.py"
        f.write_text("jupyter lab --ip=0.0.0.0 --NotebookApp.token='a-real-secret-token'\n")
        assert _rule("ns-aiml-106").check(f) == []

"""Fixtures for the generalized unsandboxed-Jinja-env SSTI detections (issue
#293): the SGLang CVE-2026-5760 class extended beyond chat_template.

Two rules, two engines:

  - TNT-ML-028 (rules/ml_taint.yaml, mode: taint): a model-metadata read
    BEYOND chat_template (generation/adapter config, AutoConfig fields,
    hf_hub_download contents -- the registry's `model_metadata` source
    fragment) flowing into an unsandboxed jinja2 render. Engine-gated: needs
    the Opengrep binary, skipped if absent (project convention -- CI does not
    install it). The canonical chat_template flow stays with TNT-ML-008, so a
    pure chat_template fixture must NOT also fire TNT-ML-028 (clean
    attribution, asserted below).

  - ns-aiml-129 (rules/ai_security.yaml, mode: regex): the structural presence
    signal -- construction of a non-sandboxed jinja2.Environment /
    get_jinja_env-style factory. Offline (load_neuroscan_rules + .check), same
    pattern as tests/test_ns_aiml_118_119_rag_isolation.py.

Companion to TNT-ML-001/008 (chat_template SSTI) and MFV-GGUF-003.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()


# ── Taint rule TNT-ML-028 (engine-gated) ──────────────────────────────
@pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)
class TestUnsandboxedJinjaEnvTaintTNTML028:
    def _scan(self, tmp_path, filename, source):
        fp = tmp_path / filename
        fp.write_text(source, encoding="utf-8")
        adapter = OpengrepAdapter()
        findings = adapter.scan_with_rules(
            tmp_path, [RULES_DIR / "ml_taint.yaml"], languages=["python"]
        )
        return findings

    def _ids(self, findings):
        return {f.rule_id for f in findings}

    def test_generation_config_unsandboxed_render_flagged(self, tmp_path):
        # Non-chat_template metadata field (generation_config) -> plain env.
        src = (
            "import jinja2\n"
            "def build(generation_config):\n"
            "    tmpl = generation_config.get('prompt_template')\n"
            "    env = jinja2.Environment()\n"
            "    return env.from_string(tmpl).render()\n"
        )
        findings = self._scan(tmp_path, "gen_config_ssti.py", src)
        assert "TNT-ML-028" in self._ids(findings), (
            "generation_config field into unsandboxed env.from_string().render() must fire TNT-ML-028"
        )

    def test_autoconfig_field_different_framework_flagged(self, tmp_path):
        # Deliberately unlike the SGLang PoC: different framework
        # (transformers AutoConfig), different metadata field (prompt_format,
        # not chat_template), different var names -- proves the rule
        # generalizes rather than pattern-matching one codebase.
        src = (
            "import jinja2\n"
            "from transformers import AutoConfig\n"
            "def render_prompt():\n"
            "    cfg = AutoConfig.from_pretrained('vendor/model')\n"
            "    renderer = jinja2.Environment()\n"
            "    out = renderer.from_string(cfg.prompt_format)\n"
            "    return out.render()\n"
        )
        findings = self._scan(tmp_path, "autoconfig_ssti.py", src)
        assert "TNT-ML-028" in self._ids(findings), (
            "AutoConfig.from_pretrained() field into an unsandboxed env must fire TNT-ML-028 (generalization)"
        )

    def test_adapter_config_template_render_flagged(self, tmp_path):
        # LoRA/adapter metadata field into a bare Template().render() (no env).
        src = (
            "from jinja2 import Template\n"
            "def apply(adapter_config):\n"
            "    fmt = adapter_config['response_format']\n"
            "    return Template(fmt).render()\n"
        )
        findings = self._scan(tmp_path, "adapter_ssti.py", src)
        assert "TNT-ML-028" in self._ids(findings), (
            "adapter_config field into Template().render() must fire TNT-ML-028"
        )

    def test_sandboxed_env_not_flagged(self, tmp_path):
        # Function-local ImmutableSandboxedEnvironment: the correct fix.
        src = (
            "from jinja2.sandbox import ImmutableSandboxedEnvironment\n"
            "def build(generation_config):\n"
            "    tmpl = generation_config.get('prompt_template')\n"
            "    env = ImmutableSandboxedEnvironment()\n"
            "    return env.from_string(tmpl).render()\n"
        )
        findings = self._scan(tmp_path, "gen_config_safe.py", src)
        assert "TNT-ML-028" not in self._ids(findings), (
            "a sandboxed env (ImmutableSandboxedEnvironment) must NOT fire TNT-ML-028"
        )

    def test_inline_sandboxed_env_not_flagged(self, tmp_path):
        src = (
            "from jinja2.sandbox import ImmutableSandboxedEnvironment\n"
            "def build(generation_config):\n"
            "    tmpl = generation_config.get('prompt_template')\n"
            "    return ImmutableSandboxedEnvironment().from_string(tmpl).render()\n"
        )
        findings = self._scan(tmp_path, "inline_safe.py", src)
        assert "TNT-ML-028" not in self._ids(findings), (
            "an inline sandboxed env must NOT fire TNT-ML-028"
        )

    def test_chat_template_flow_not_double_reported(self, tmp_path):
        # The canonical chat_template flow is owned by TNT-ML-008. TNT-ML-028's
        # source set deliberately omits the chat_template attribute reads, so it
        # must NOT also fire here -- attribution stays clean.
        src = (
            "from jinja2 import Template\n"
            "def build(tokenizer):\n"
            "    t = tokenizer.chat_template\n"
            "    return Template(t).render()\n"
        )
        findings = self._scan(tmp_path, "chat_template_flow.py", src)
        ids = self._ids(findings)
        assert "TNT-ML-028" not in ids, (
            "a pure chat_template flow must NOT fire TNT-ML-028 (owned by TNT-ML-008)"
        )
        assert "TNT-ML-008" in ids, (
            "the chat_template flow must still be caught by its owner TNT-ML-008"
        )


# ── Regex fallback ns-aiml-129 (offline) ──────────────────────────────
def _regex_rule(rule_id):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestUnsandboxedJinjaEnvRegexNsAiml129:
    def test_sglang_get_jinja_env_factory_flagged(self, tmp_path):
        fp = tmp_path / "sglang_env.py"
        fp.write_text(
            "import sglang\n"
            "import jinja2\n"
            "def get_jinja_env():\n"
            "    env = jinja2.Environment()\n"
            "    return env\n",
            encoding="utf-8",
        )
        assert _regex_rule("ns-aiml-129").check(fp), (
            "get_jinja_env building a plain jinja2.Environment must be flagged"
        )

    def test_vllm_bare_environment_flagged(self, tmp_path):
        fp = tmp_path / "vllm_env.py"
        fp.write_text(
            "from vllm import LLM\n"
            "from jinja2 import Environment\n"
            "def make_prompt(cfg):\n"
            "    env = Environment()\n"
            "    return env.from_string(cfg['prompt_format'])\n",
            encoding="utf-8",
        )
        assert _regex_rule("ns-aiml-129").check(fp), (
            "a bare Environment() construction in a vllm file must be flagged"
        )

    def test_sandboxed_serving_env_not_flagged(self, tmp_path):
        fp = tmp_path / "sglang_safe.py"
        fp.write_text(
            "import sglang\n"
            "from jinja2.sandbox import ImmutableSandboxedEnvironment\n"
            "def get_jinja_env():\n"
            "    env = ImmutableSandboxedEnvironment()\n"
            "    return env\n",
            encoding="utf-8",
        )
        assert _regex_rule("ns-aiml-129").check(fp) == [], (
            "a sandboxed serving env must NOT be flagged by ns-aiml-129"
        )

    def test_plain_flask_render_template_not_flagged(self, tmp_path):
        # The FP the gate exists to prevent: an ordinary Flask app using
        # render_template does not construct a raw jinja2.Environment.
        fp = tmp_path / "webapp.py"
        fp.write_text(
            "from flask import Flask, render_template\n"
            "app = Flask(__name__)\n"
            "@app.route('/')\n"
            "def index():\n"
            "    return render_template('index.html', name='x')\n",
            encoding="utf-8",
        )
        assert _regex_rule("ns-aiml-129").check(fp) == [], (
            "a plain Flask render_template app must NOT be flagged by ns-aiml-129"
        )

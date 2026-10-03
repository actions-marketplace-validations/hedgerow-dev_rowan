"""Positive/negative fixtures for TNT-ML-012 / TNT-ML-017 (rules/agent_taint.yaml,
issue #135: raw reflection dispatch on a model-chosen tool/function name).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).

Rule split:
  - TNT-ML-012: model-chosen name -> getattr($OBJ, $NAME) (pre-existing,
    extended here with an Anthropic tool_use content-block source and
    reassignment-style Enum/allow-list-dict sanitizers).
  - TNT-ML-017 (new): model-chosen name -> globals()[$NAME] / locals()[$NAME]
    / importlib.import_module($NAME) -- the non-getattr reflection sinks
    named in #135. Disjoint sink set from TNT-ML-012, so the two never
    double-fire on the same sink expression.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "agent_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestGetattrDispatchTNTML012:
    """TNT-ML-012: model-chosen name reaching getattr()."""

    def test_openai_sdk_shape_flagged(self, tmp_path):
        src = (
            "def run(self, response):\n"
            "    for tool_call in response.choices[0].message.tool_calls:\n"
            "        fn = getattr(self, tool_call.function.name)\n"
            "        result = fn(**json.loads(tool_call.function.arguments))\n"
        )
        findings = _scan(tmp_path, "openai_agent.py", src, "TNT-ML-012")
        assert findings, "OpenAI tool_call.function.name into getattr() must be flagged"

    def test_anthropic_sdk_tool_use_block_shape_flagged(self, tmp_path):
        # Anthropic Messages API tool_use content block shape: type="tool_use",
        # id, name, input (see anthropic.types.ToolUseBlock).
        src = (
            "def run(self, message):\n"
            "    for content_block in message.content:\n"
            "        if content_block.type == 'tool_use':\n"
            "            fn = getattr(self, content_block.name)\n"
            "            result = fn(**content_block.input)\n"
        )
        findings = _scan(tmp_path, "anthropic_agent.py", src, "TNT-ML-012")
        assert findings, "Anthropic tool_use content_block.name into getattr() must be flagged"

    def test_litellm_shape_flagged(self, tmp_path):
        # litellm.completion() returns an OpenAI-API-compatible response,
        # so the tool-call shape is identical to the raw OpenAI SDK.
        src = (
            "import litellm\n\n"
            "def run(self, messages):\n"
            "    response = litellm.completion(model='gpt-4o', messages=messages)\n"
            "    tool_call = response.choices[0].message.tool_calls[0]\n"
            "    fn = getattr(self, tool_call.function.name)\n"
            "    result = fn(**json.loads(tool_call.function.arguments))\n"
        )
        findings = _scan(tmp_path, "litellm_agent.py", src, "TNT-ML-012")
        assert findings, "litellm tool_call.function.name into getattr() must be flagged"

    def test_dict_literal_allowlist_not_flagged(self, tmp_path):
        # Clean by construction: TOOLS[name] is a plain dict subscript, not
        # one of this rule's sink shapes (getattr/globals/locals/import_module).
        src = (
            "TOOLS = {'search': search, 'calc': calc}\n\n"
            "def run(self, call):\n"
            "    fn = TOOLS[call.function.name]\n"
            "    result = fn()\n"
        )
        findings = _scan(tmp_path, "dict_allowlist_agent.py", src, "TNT-ML-012")
        assert findings == [], "a dict-literal allow-list lookup must not be flagged"

    def test_enum_validation_not_flagged(self, tmp_path):
        src = (
            "from enum import Enum\n\n"
            "class ToolName(Enum):\n"
            "    SEARCH = 'search'\n"
            "    CALC = 'calc'\n\n"
            "def run(self, call):\n"
            "    name = call.function.name\n"
            "    name = ToolName(name).value\n"
            "    fn = getattr(self, name)\n"
            "    result = fn()\n"
        )
        findings = _scan(tmp_path, "enum_validated_agent.py", src, "TNT-ML-012")
        assert findings == [], "an Enum-validated (reassigned) name must not be flagged"

    def test_unrelated_dot_name_attribute_not_flagged(self, tmp_path):
        # The FP class this whole rule family is built to avoid: a bare
        # `.name` attribute access unrelated to any tool call (e.g. a
        # user's own .name field) must not be treated as a taint source.
        src = (
            "def run(self, obj, user):\n"
            "    x = getattr(obj, user.name)\n"
            "    return x\n"
        )
        findings = _scan(tmp_path, "unrelated_name_attr.py", src, "TNT-ML-012")
        assert findings == [], "a bare unrelated .name attribute access must not be flagged"


class TestNonGetattrDispatchTNTML017:
    """TNT-ML-017: model-chosen name reaching globals()/locals()/import_module()."""

    def test_globals_dispatch_flagged(self, tmp_path):
        src = (
            "def run(self, response):\n"
            "    tool_call = response.choices[0].message.tool_calls[0]\n"
            "    fn = globals()[tool_call.function.name]\n"
            "    result = fn()\n"
        )
        findings = _scan(tmp_path, "globals_agent.py", src, "TNT-ML-017")
        assert findings, "tool_call.function.name into globals()[...] must be flagged"

    def test_locals_dispatch_flagged(self, tmp_path):
        src = (
            "def run(self, response):\n"
            "    tool_call = response.choices[0].message.tool_calls[0]\n"
            "    fn = locals()[tool_call.function.name]\n"
            "    result = fn()\n"
        )
        findings = _scan(tmp_path, "locals_agent.py", src, "TNT-ML-017")
        assert findings, "tool_call.function.name into locals()[...] must be flagged"

    def test_import_module_dispatch_flagged(self, tmp_path):
        src = (
            "import importlib\n\n"
            "def run(self, response):\n"
            "    tool_call = response.choices[0].message.tool_calls[0]\n"
            "    mod = importlib.import_module(tool_call.function.name)\n"
            "    result = mod.run()\n"
        )
        findings = _scan(tmp_path, "import_module_agent.py", src, "TNT-ML-017")
        assert findings, "tool_call.function.name into importlib.import_module() must be flagged"

    def test_anthropic_shape_into_globals_flagged(self, tmp_path):
        src = (
            "def run(self, message):\n"
            "    for content_block in message.content:\n"
            "        if content_block.type == 'tool_use':\n"
            "            fn = globals()[content_block.name]\n"
            "            result = fn(**content_block.input)\n"
        )
        findings = _scan(tmp_path, "anthropic_globals_agent.py", src, "TNT-ML-017")
        assert findings, "Anthropic content_block.name into globals()[...] must be flagged"

    def test_dict_literal_allowlist_not_flagged(self, tmp_path):
        src = (
            "TOOLS = {'search': search, 'calc': calc}\n\n"
            "def run(self, call):\n"
            "    fn = TOOLS[call.function.name]\n"
            "    result = fn()\n"
        )
        findings = _scan(tmp_path, "dict_allowlist_agent2.py", src, "TNT-ML-017")
        assert findings == [], "a dict-literal allow-list lookup must not be flagged"

    def test_enum_validation_not_flagged(self, tmp_path):
        src = (
            "from enum import Enum\n\n"
            "class ToolName(Enum):\n"
            "    SEARCH = 'search'\n"
            "    CALC = 'calc'\n\n"
            "def run(self, call):\n"
            "    name = call.function.name\n"
            "    name = ToolName(name).value\n"
            "    fn = globals()[name]\n"
            "    result = fn()\n"
        )
        findings = _scan(tmp_path, "enum_validated_agent2.py", src, "TNT-ML-017")
        assert findings == [], "an Enum-validated (reassigned) name must not be flagged"

    def test_no_double_fire_with_tnt_ml_012_on_getattr_line(self, tmp_path):
        # Same source reaching a getattr() sink must only ever be reported
        # by TNT-ML-012, never also by TNT-ML-017 (disjoint sink shapes).
        src = (
            "def run(self, response):\n"
            "    tool_call = response.choices[0].message.tool_calls[0]\n"
            "    fn = getattr(self, tool_call.function.name)\n"
            "    result = fn()\n"
        )
        fp = tmp_path / "getattr_only.py"
        fp.write_text(src, encoding="utf-8")
        adapter = OpengrepAdapter()
        findings = adapter.scan_with_rules(
            tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
        )
        rule_ids = {f.rule_id for f in findings}
        assert "TNT-ML-012" in rule_ids
        assert "TNT-ML-017" not in rule_ids, (
            "TNT-ML-017 must not also fire on a getattr() sink already covered by TNT-ML-012"
        )

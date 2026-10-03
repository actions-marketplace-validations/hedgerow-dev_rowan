"""Tests for ns-aiml-110 (rules/ai_security.yaml): raw reflection-dispatch
presence signal, the companion regex rule to TNT-ML-012 / TNT-ML-017
(issue #135) for the single-statement case the taint engine's
pattern-sources/pattern-sinks split can miss.
"""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule():
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == "ns-aiml-110")


def test_openai_getattr_one_liner_flagged(tmp_path):
    fp = tmp_path / "openai_agent.py"
    fp.write_text(
        "def run(self, tool_call):\n"
        "    fn = getattr(self, tool_call.function.name)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "getattr(self, tool_call.function.name) one-liner must be flagged"


def test_dict_subscript_variant_flagged(tmp_path):
    fp = tmp_path / "dict_variant.py"
    fp.write_text(
        "def run(self, call):\n"
        "    fn = getattr(self, call['function']['name'])\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), 'getattr(self, call["function"]["name"]) must be flagged'


def test_anthropic_content_block_getattr_flagged(tmp_path):
    fp = tmp_path / "anthropic_agent.py"
    fp.write_text(
        "def run(self, content_block):\n"
        "    fn = getattr(self, content_block.name)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "getattr(self, content_block.name) must be flagged"


def test_globals_dispatch_flagged(tmp_path):
    fp = tmp_path / "globals_agent.py"
    fp.write_text(
        "def run(self, tool_call):\n"
        "    fn = globals()[tool_call.function.name]\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "globals()[tool_call.function.name] must be flagged"


def test_locals_dispatch_flagged(tmp_path):
    fp = tmp_path / "locals_agent.py"
    fp.write_text(
        "def run(self, tool_call):\n"
        "    fn = locals()[tool_call.function.name]\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "locals()[tool_call.function.name] must be flagged"


def test_import_module_dispatch_flagged(tmp_path):
    fp = tmp_path / "import_module_agent.py"
    fp.write_text(
        "import importlib\n\n"
        "def run(self, tool_call):\n"
        "    mod = importlib.import_module(tool_call.function.name)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp), "importlib.import_module(tool_call.function.name) must be flagged"


def test_dict_literal_allowlist_not_flagged(tmp_path):
    fp = tmp_path / "dict_allowlist_agent.py"
    fp.write_text(
        "TOOLS = {'search': search, 'calc': calc}\n\n"
        "def run(self, call):\n"
        "    fn = TOOLS[call.function.name]\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "a dict-literal allow-list lookup must not be flagged"


def test_enum_validated_dispatch_not_flagged(tmp_path):
    fp = tmp_path / "enum_validated_agent.py"
    fp.write_text(
        "from enum import Enum\n\n"
        "class ToolName(Enum):\n"
        "    SEARCH = 'search'\n\n"
        "def run(self, call):\n"
        "    name = ToolName(call.function.name).value\n"
        "    fn = getattr(self, name)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "an Enum-validated dispatch must not be flagged"


def test_unrelated_dot_name_attribute_not_flagged(tmp_path):
    fp = tmp_path / "unrelated_name_attr.py"
    fp.write_text(
        "def run(self, obj, user):\n"
        "    x = getattr(obj, user.name)\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "a bare unrelated .name attribute access must not be flagged"


def test_comment_only_mention_not_flagged(tmp_path):
    fp = tmp_path / "notes.py"
    fp.write_text(
        "# TODO: consider getattr(self, tool_call.function.name) for dispatch\n",
        encoding="utf-8",
    )
    assert _rule().check(fp) == [], "a commented-out mention must not be flagged"

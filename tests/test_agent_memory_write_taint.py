"""Positive/negative fixtures for TNT-ML-018 / TNT-ML-019
(rules/agent_taint.yaml, issue #136: agent-memory write-path poisoning).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).

Rule split (see the rules' own engine notes in rules/agent_taint.yaml for the
full rationale):
  - TNT-ML-018: a request/user-supplied value flows into a persistent
    agent-memory write call (mem0 Memory().add()/$MEM.add(), LangGraph
    store.put()/aput(), CrewAI-style memory.save()) -- threat-model item 1
    from the issue ("remember that ..." becomes standing instructions).
  - TNT-ML-019: an LLM completion flows into the same sink family --
    threat-model item 3 from the issue (a laundered indirect-injection
    payload gets written down as "the agent's own notes").

Letta's archival_memory_insert/core_memory_append/core_memory_replace are
deliberately NOT covered here -- see TNT-ML-018's engine note for why (the
model's own tool-call decision is the source, not a traceable in-file
expression). That shape is covered by ns-aiml-112
(tests/test_ns_aiml_111_112_memory_write.py) instead.
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


class TestRequestToMemoryWriteTNTML018:
    """TNT-ML-018: request/user-message source -> memory-write sink."""

    def test_mem0_add_flagged(self, tmp_path):
        src = (
            "def run():\n"
            "    user_message = request.json.get('message')\n"
            "    memory = Memory()\n"
            "    memory.add(user_message, user_id='u1')\n"
        )
        findings = _scan(tmp_path, "mem0_agent.py", src, "TNT-ML-018")
        assert findings, "request.json.get(...) into mem0 memory.add() must be flagged"

    def test_memory_chained_constructor_add_flagged(self, tmp_path):
        src = (
            "def run():\n"
            "    note = data.get('note')\n"
            "    Memory().add(note)\n"
        )
        findings = _scan(tmp_path, "mem0_chained.py", src, "TNT-ML-018")
        assert findings, "data.get(...) into Memory().add() must be flagged"

    def test_langgraph_store_put_flagged(self, tmp_path):
        src = (
            "def run(store):\n"
            "    note = request.form.get('note')\n"
            "    store.put(('memories', 'u1'), 'note', note)\n"
        )
        findings = _scan(tmp_path, "langgraph_agent.py", src, "TNT-ML-018")
        assert findings, "request.form.get(...) into store.put() must be flagged"

    def test_crewai_memory_save_flagged(self, tmp_path):
        src = (
            "def run(memory):\n"
            "    note = data.get('note')\n"
            "    memory.save(note)\n"
        )
        findings = _scan(tmp_path, "crewai_agent.py", src, "TNT-ML-018")
        assert findings, "data.get(...) into a memory.save() call must be flagged"

    def test_moderation_validated_value_not_flagged(self, tmp_path):
        src = (
            "def run(client):\n"
            "    user_message = request.json.get('message')\n"
            "    checked = client.moderations.create(input=user_message)\n"
            "    memory = Memory()\n"
            "    memory.add(checked, user_id='u1')\n"
        )
        findings = _scan(tmp_path, "mem0_moderated.py", src, "TNT-ML-018")
        assert not findings, (
            "a value that passed through client.moderations.create(...) "
            "before reaching the memory-write sink must not be flagged"
        )

    def test_unrelated_set_add_not_flagged(self, tmp_path):
        # FP guard: a hint-word-unrelated receiver's .add() must not fire --
        # same collision class TNT-ML-016's engine note already documented
        # for list.add()/set.add().
        src = (
            "def run():\n"
            "    user_message = request.json.get('message')\n"
            "    tags = set()\n"
            "    tags.add(user_message)\n"
        )
        findings = _scan(tmp_path, "unrelated_set_add.py", src, "TNT-ML-018")
        assert not findings, "set.add() with no memory-shaped receiver must not be flagged"


class TestLLMCompletionToMemoryWriteTNTML019:
    """TNT-ML-019: LLM completion source -> memory-write sink."""

    def test_openai_completion_into_mem0_add_flagged(self, tmp_path):
        src = (
            "def run(client, messages):\n"
            "    resp = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
            "    content = resp.choices[0].message.content\n"
            "    memory = Memory()\n"
            "    memory.add(content, user_id='u1')\n"
        )
        findings = _scan(tmp_path, "mem0_llm_write.py", src, "TNT-ML-019")
        assert findings, "LLM completion content into mem0 mem.add() must be flagged"

    def test_streaming_accumulation_into_store_put_flagged(self, tmp_path):
        src = (
            "def run(client, messages, store):\n"
            "    full = ''\n"
            "    for chunk in client.chat.completions.create(model='gpt-4o', messages=messages, stream=True):\n"
            "        full += chunk.choices[0].delta.content\n"
            "    store.put(('memories', 'u1'), 'note', full)\n"
        )
        findings = _scan(tmp_path, "langgraph_llm_stream_write.py", src, "TNT-ML-019")
        assert findings, (
            "streaming delta accumulated into a variable that reaches "
            "store.put() must be flagged"
        )

    def test_pydantic_validated_completion_not_flagged(self, tmp_path):
        src = (
            "from pydantic import BaseModel\n\n"
            "class Note(BaseModel):\n"
            "    text: str\n\n"
            "def run(client, messages):\n"
            "    resp = client.chat.completions.create(model='gpt-4o', messages=messages)\n"
            "    raw = resp.choices[0].message.content\n"
            "    validated = Note.model_validate_json(raw)\n"
            "    memory = Memory()\n"
            "    memory.add(validated, user_id='u1')\n"
        )
        findings = _scan(tmp_path, "mem0_llm_validated.py", src, "TNT-ML-019")
        assert not findings, (
            "completion text validated through a Pydantic structured-output "
            "model before reaching the memory-write sink must not be flagged"
        )

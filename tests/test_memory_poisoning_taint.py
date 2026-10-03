"""Positive/negative fixtures for TNT-ML-029 (rules/agent_taint.yaml, issue
#294: two-hop agent memory poisoning -- MINJA / AgentPoison / PoisonedRAG).

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention -- CI does not install it, see .github/workflows/ci.yml).

TNT-ML-029 is the PAIRED write-then-read finding: untrusted content (an LLM
completion or a request value) persisted into a memory/RAG store and later
read back, unscoped, into a prompt/LLM/tool sink in the same flow. It is kept
deliberately distinct from its three neighbours, each of which models only one
hop:
  - TNT-ML-016 models the READ hop alone (recall unscoped into a prompt); a
    lone read with no write must stay owned by TNT-ML-016, not TNT-ML-029.
  - TNT-ML-018/019 model the WRITE hop alone (untrusted value persisted); a
    write with no read-back, and the direct one-hop shape where the same
    value is prompted without round-tripping through the store, must not fire
    TNT-ML-029.

The rule uses labeled taint (UNTRUSTED source -> WRITE propagator stamps
PERSISTED on the store object -> receiver-propagated read inherits PERSISTED
-> sink requires PERSISTED), so both hops are structurally required. See the
rule's own engine note in rules/agent_taint.yaml for the full rationale.
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


class TestTwoHopMemoryPoisoningFires:
    """(a) untrusted write -> later read -> prompt must fire TNT-ML-029."""

    def test_llm_completion_written_then_recalled_into_prompt(self, tmp_path):
        src = (
            "def handle(client, memory, llm, user_msg):\n"
            "    resp = client.chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': user_msg}])\n"
            "    text = resp.choices[0].message.content\n"
            "    memory.add(text)\n"
            "    recalled = memory.search('recent notes')\n"
            "    prompt = f'Context: {recalled}\\nAnswer the user.'\n"
            "    return llm.generate(prompt)\n"
        )
        findings = _scan(tmp_path, "poison_llm.py", src, "TNT-ML-029")
        assert findings, (
            "LLM output -> memory.add -> later memory.search -> prompt must fire TNT-ML-029"
        )

    def test_request_value_written_then_recalled_into_prompt(self, tmp_path):
        src = (
            "def handle(memory, llm):\n"
            "    note = request.json.get('note')\n"
            "    memory.add(note)\n"
            "    recalled = memory.search('recent notes')\n"
            "    return llm.generate(f'Context: {recalled}')\n"
        )
        findings = _scan(tmp_path, "poison_req.py", src, "TNT-ML-029")
        assert findings, (
            "request value -> memory.add -> later memory.search -> prompt must fire TNT-ML-029"
        )

    def test_generalises_to_a_different_client_and_var_names(self, tmp_path):
        # Deliberately unlike any single PoC: a LangChain-style vectorstore
        # (add_texts/similarity_search, not mem0 add/search), different
        # variable names, a request source, and an agent .invoke() sink.
        src = (
            "def langchain_flow(vectorstore, chatbot):\n"
            "    note = request.json.get('note')\n"
            "    vectorstore.add_texts([note])\n"
            "    hits = vectorstore.similarity_search('topic')\n"
            "    return chatbot.invoke(f'Relevant: {hits}')\n"
        )
        findings = _scan(tmp_path, "poison_langchain.py", src, "TNT-ML-029")
        assert findings, (
            "the write-then-read class must generalise across memory/RAG clients "
            "(LangChain vectorstore add_texts/similarity_search), not just one PoC"
        )

    def test_generalises_to_raw_pinecone_upsert_then_query(self, tmp_path):
        # A raw Pinecone index: upsert() write, query() read whose method name
        # is NOT enumerated anywhere in the rule -- it fires only because taint
        # is receiver-propagated from the poisoned store object, which is what
        # makes the rule generalise across read APIs.
        src = (
            "def pinecone_flow(pc_index, assistant):\n"
            "    payload = request.args.get('doc')\n"
            "    pc_index.upsert([(1, payload)])\n"
            "    matches = pc_index.query(top_k=3)\n"
            "    return assistant.generate(f'Docs: {matches}')\n"
        )
        findings = _scan(tmp_path, "poison_pinecone.py", src, "TNT-ML-029")
        assert findings, (
            "raw Pinecone upsert -> query -> prompt must fire via receiver taint propagation"
        )


class TestTwoHopMemoryPoisoningDoesNotFire:
    """(b) scoped/validated variants, static writes, and one-hop shapes must
    not fire TNT-ML-029."""

    def test_per_tenant_scoped_read_not_flagged(self, tmp_path):
        src = (
            "def handle(client, memory, llm, uid, user_msg):\n"
            "    resp = client.chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': user_msg}])\n"
            "    text = resp.choices[0].message.content\n"
            "    memory.add(text, user_id=uid)\n"
            "    recalled = memory.search('recent notes', user_id=uid)\n"
            "    return llm.generate(f'Context: {recalled}')\n"
        )
        findings = _scan(tmp_path, "scoped.py", src, "TNT-ML-029")
        assert findings == [], (
            "a recall scoped to the caller's user_id (ns-aiml-111 control) must not fire TNT-ML-029"
        )

    def test_explicit_validation_between_read_and_prompt_not_flagged(self, tmp_path):
        src = (
            "def handle(client, memory, llm, RecordModel, user_msg):\n"
            "    resp = client.chat.completions.create(model='gpt-4', messages=[{'role': 'user', 'content': user_msg}])\n"
            "    text = resp.choices[0].message.content\n"
            "    memory.add(text)\n"
            "    recalled = memory.search('recent notes')\n"
            "    clean = RecordModel.model_validate(recalled)\n"
            "    return llm.generate(f'Context: {clean}')\n"
        )
        findings = _scan(tmp_path, "validated.py", src, "TNT-ML-029")
        assert findings == [], (
            "an explicit model_validate() step between read and prompt must sanitize the flow"
        )

    def test_static_write_content_not_flagged(self, tmp_path):
        src = (
            "def handle(memory, llm):\n"
            "    memory.add('You are a helpful assistant.')\n"
            "    recalled = memory.search('recent notes')\n"
            "    return llm.generate(f'Context: {recalled}')\n"
        )
        findings = _scan(tmp_path, "static_write.py", src, "TNT-ML-029")
        assert findings == [], (
            "a static/system-string write is never UNTRUSTED, so the read-back must not fire TNT-ML-029"
        )

    def test_direct_llm_output_to_prompt_without_readback_not_flagged(self, tmp_path):
        # The one-hop shape: the SAME LLM output is put straight into a prompt
        # and also (incidentally) written to memory, but never read back. This
        # is TNT-ML-005/019 territory, not the two-hop class -- TNT-ML-029 must
        # not fire because the value reaching the prompt did not round-trip
        # through the store.
        src = (
            "def handle(client, memory, llm):\n"
            "    resp = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    text = resp.choices[0].message.content\n"
            "    memory.add(text)\n"
            "    return llm.generate(f'Say: {text}')\n"
        )
        findings = _scan(tmp_path, "direct.py", src, "TNT-ML-029")
        assert findings == [], (
            "a direct LLM-output -> prompt flow that never reads back from the store "
            "must not fire TNT-ML-029 (both hops are required)"
        )


class TestLoneReadStaysOwnedByTNTML016:
    """(c) a lone read -> prompt (no write anywhere) is TNT-ML-016's finding,
    not TNT-ML-029's."""

    _LONE_READ = (
        "def lone_read(memory, llm):\n"
        "    recalled = memory.search('recent notes')\n"
        "    return llm.generate(f'Context: {recalled}')\n"
    )

    def test_lone_read_does_not_fire_tnt_ml_029(self, tmp_path):
        findings = _scan(tmp_path, "lone_read_029.py", self._LONE_READ, "TNT-ML-029")
        assert findings == [], (
            "a lone read with no write hop must not fire the two-hop rule TNT-ML-029"
        )

    def test_lone_read_is_owned_by_tnt_ml_016(self, tmp_path):
        findings = _scan(tmp_path, "lone_read_016.py", self._LONE_READ, "TNT-ML-016")
        assert findings, (
            "the lone read -> prompt shape must still be caught by TNT-ML-016 (its owner)"
        )

"""Tests for ns-aiml-111 / ns-aiml-112 (rules/ai_security.yaml): agent-memory
write-path presence signals, companions to TNT-ML-018/019 (issue #136) for
the shapes a same-file taint flow either can't reach (ns-aiml-111's
missing-scoping check is a structural "what argument is absent" question,
not a source-to-sink dataflow one) or shouldn't try to (ns-aiml-112's Letta
agent-tool shape -- see TNT-ML-018's engine note in rules/agent_taint.yaml).
"""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestNsAiml111MissingScoping:
    def test_mem0_add_missing_user_id_flagged(self, tmp_path):
        fp = tmp_path / "mem0_unscoped.py"
        fp.write_text(
            "def run(user_message):\n"
            "    memory = Memory()\n"
            "    memory.add(user_message)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp), (
            "mem0 memory.add(...) with no user_id= kwarg must be flagged"
        )

    def test_mem0_add_with_user_id_not_flagged(self, tmp_path):
        fp = tmp_path / "mem0_scoped.py"
        fp.write_text(
            "def run(user_message):\n"
            "    memory = Memory()\n"
            "    memory.add(user_message, user_id='u1')\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp) == [], (
            "mem0 memory.add(..., user_id=...) must not be flagged"
        )

    def test_langgraph_constant_namespace_tuple_flagged(self, tmp_path):
        fp = tmp_path / "langgraph_shared_ns.py"
        fp.write_text(
            "def run(store, value):\n"
            "    store.put(('memories', 'global'), 'note', value)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp), (
            "store.put() with an all-string-literal namespace tuple must be flagged"
        )

    def test_langgraph_variable_namespace_tuple_not_flagged(self, tmp_path):
        fp = tmp_path / "langgraph_scoped_ns.py"
        fp.write_text(
            "def run(store, user_id, value):\n"
            "    store.put(('memories', user_id), 'note', value)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp) == [], (
            "store.put() with a variable-derived namespace element must not be flagged"
        )

    def test_unrelated_set_add_not_flagged(self, tmp_path):
        fp = tmp_path / "unrelated_set_add.py"
        fp.write_text(
            "def run():\n"
            "    tags = set()\n"
            "    tags.add('x')\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp) == [], (
            "a hint-word-unrelated receiver's .add() must not be flagged"
        )

    def test_websocket_clients_registry_add_not_flagged(self, tmp_path):
        """Regression guard: found scanning scan-targets/letta --
        `self.clients.add(websocket)` (a WebSocket client-registry set, from
        letta/server/ws_api/interface.py) previously matched because bare
        "client" was in the hint-word alternation and "client" is a
        substring of "clients". mem0's real MemoryClient() SDK class is
        matched by its own word-bounded alternative instead."""
        fp = tmp_path / "ws_registry.py"
        fp.write_text(
            "class ConnectionManager:\n"
            "    def __init__(self):\n"
            "        self.clients = set()\n\n"
            "    def register_client(self, websocket):\n"
            "        self.clients.add(websocket)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp) == [], (
            "a WebSocket client-registry set().add() must not be flagged as "
            "an unscoped agent-memory write"
        )

    def test_memory_client_inline_add_still_flagged(self, tmp_path):
        """Positive control for the fix above: mem0's real MemoryClient()
        SDK class must still be caught via its own word-bounded pattern for
        the inline-call shape. A variable-assigned `mc = MemoryClient();
        mc.add(...)` is an accepted recall gap (same class as the existing
        `m = Memory(); m.add(...)` gap this rule already documents) --
        a regex has no cross-statement type tracking to recover that `mc`
        was constructed from MemoryClient()."""
        fp = tmp_path / "mem0_client.py"
        fp.write_text(
            "def run(user_message):\n"
            "    MemoryClient().add(user_message)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-111").check(fp), (
            "MemoryClient().add(...) must still be flagged"
        )


class TestNsAiml112LettaAgentToolShape:
    def test_archival_memory_insert_def_flagged(self, tmp_path):
        fp = tmp_path / "letta_tools.py"
        fp.write_text(
            "async def archival_memory_insert(self, content: str, tags=None):\n"
            "    pass\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-112").check(fp), (
            "archival_memory_insert tool definition must be flagged"
        )

    def test_archival_memory_insert_call_flagged(self, tmp_path):
        fp = tmp_path / "letta_call.py"
        fp.write_text(
            "def run(self, note):\n"
            "    self.archival_memory_insert(note)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-112").check(fp), (
            "archival_memory_insert(...) call must be flagged"
        )

    def test_core_memory_append_flagged(self, tmp_path):
        fp = tmp_path / "letta_append.py"
        fp.write_text(
            "def core_memory_append(self, label, content):\n"
            "    pass\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-112").check(fp), "core_memory_append definition must be flagged"

    def test_core_memory_replace_flagged(self, tmp_path):
        fp = tmp_path / "letta_replace.py"
        fp.write_text(
            "def core_memory_replace(self, label, old, new):\n"
            "    pass\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-112").check(fp), "core_memory_replace definition must be flagged"

    def test_comment_only_mention_not_flagged(self, tmp_path):
        fp = tmp_path / "letta_comment.py"
        fp.write_text(
            "# archival_memory_insert is used elsewhere in this agent\n"
            "def run():\n"
            "    pass\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-112").check(fp) == [], "a comment-only mention must not be flagged"

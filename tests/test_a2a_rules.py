"""Tests for the A2A regex fallbacks (rules/ai_security.yaml, issue #289):
A2A-BIND-001 and A2A-CARD-001.

These are the offline regex siblings of the A2A taint rules in
rules/a2a_taint.yaml -- the two shapes there is no dataflow to model. They
follow the exact shape of ns-aiml-126 and are anchored on A2A-specific
identifiers (A2AServer / A2AStarletteApplication / AgentCard) so they do not
fire on generic Starlette/FastAPI code.

  - A2A-BIND-001: an A2A server bound to 0.0.0.0 with no visible auth.
  - A2A-CARD-001: an AgentCard constructed with no security-scheme key in the
    surrounding literal.
"""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestA2ABind001:
    def test_a2a_server_bound_all_interfaces_flagged(self, tmp_path):
        fp = tmp_path / "a2a_server.py"
        fp.write_text(
            "def main():\n"
            "    server = A2AServer(host='0.0.0.0', port=5000)\n"
            "    server.start()\n",
            encoding="utf-8",
        )
        assert _rule("A2A-BIND-001").check(fp), (
            "A2AServer bound to 0.0.0.0 must be flagged"
        )

    def test_a2a_serve_call_bound_all_interfaces_flagged(self, tmp_path):
        """Different shape: a bare a2a serve call rather than the constructor,
        proving the rule keys off the A2A identifier, not one exact form."""
        fp = tmp_path / "a2a_serve.py"
        fp.write_text(
            "def run():\n"
            "    a2a_app.serve(host='0.0.0.0', port=8000)\n",
            encoding="utf-8",
        )
        assert _rule("A2A-BIND-001").check(fp), (
            "an a2a_app.serve(host='0.0.0.0') call must be flagged"
        )

    def test_a2a_server_with_auth_not_flagged(self, tmp_path):
        fp = tmp_path / "a2a_server_auth.py"
        fp.write_text(
            "def main():\n"
            "    server = A2AServer(host='0.0.0.0', auth_provider=BearerAuth())\n",
            encoding="utf-8",
        )
        assert _rule("A2A-BIND-001").check(fp) == [], (
            "an A2AServer with a visible auth_provider must not be flagged"
        )

    def test_a2a_server_localhost_not_flagged(self, tmp_path):
        fp = tmp_path / "a2a_local.py"
        fp.write_text(
            "def main():\n"
            "    server = A2AServer(host='127.0.0.1', port=5000)\n",
            encoding="utf-8",
        )
        assert _rule("A2A-BIND-001").check(fp) == [], (
            "an A2A server bound to localhost must not be flagged"
        )

    def test_generic_starlette_bind_not_flagged(self, tmp_path):
        """Precision guard: a generic (non-A2A) 0.0.0.0 bind must not fire --
        this is the anchoring the spec requires."""
        fp = tmp_path / "generic.py"
        fp.write_text(
            "def main():\n"
            "    app = Starlette()\n"
            "    uvicorn.run(app, host='0.0.0.0')\n",
            encoding="utf-8",
        )
        assert _rule("A2A-BIND-001").check(fp) == [], (
            "a generic non-A2A 0.0.0.0 bind must not be flagged by A2A-BIND-001"
        )


class TestA2ACard001:
    def test_agent_card_without_security_scheme_flagged(self, tmp_path):
        fp = tmp_path / "card.py"
        fp.write_text(
            "def build():\n"
            "    return AgentCard(name='billing', skills=[skill], url='http://svc')\n",
            encoding="utf-8",
        )
        assert _rule("A2A-CARD-001").check(fp), (
            "an AgentCard with no security-scheme key must be flagged"
        )

    def test_agent_card_with_security_scheme_not_flagged(self, tmp_path):
        fp = tmp_path / "card_secure.py"
        fp.write_text(
            "def build():\n"
            "    return AgentCard(\n"
            "        name='billing',\n"
            "        skills=[skill],\n"
            "        security_schemes={'bearer': BearerScheme()},\n"
            "    )\n",
            encoding="utf-8",
        )
        assert _rule("A2A-CARD-001").check(fp) == [], (
            "an AgentCard declaring a security_schemes= key must not be flagged"
        )

    def test_unrelated_dataclass_not_flagged(self, tmp_path):
        """Precision guard: a same-named-but-unrelated construction that is not
        an AgentCard must not fire."""
        fp = tmp_path / "unrelated.py"
        fp.write_text(
            "def build():\n"
            "    return BusinessCard(name='billing')\n",
            encoding="utf-8",
        )
        assert _rule("A2A-CARD-001").check(fp) == [], (
            "an unrelated non-AgentCard construction must not be flagged"
        )

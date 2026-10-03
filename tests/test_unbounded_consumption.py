"""Fixtures for the unbounded-consumption / denial-of-wallet rule family
(GitHub issue #139, OWASP LLM10:2025).

Four rules:
  - TNT-ML-022 (rules/ml_taint.yaml, taint): request-derived value flows
    into max_tokens/n/best_of/max_completion_tokens of a completion API
    call.
  - ns-aiml-120 (rules/ai_security.yaml, regex presence): `while True:`/
    `while 1:` loop with no visible iteration-cap term nearby.
  - ns-aiml-121 (rules/ai_security.yaml, regex presence): a completion API
    call with no max_tokens/max_completion_tokens/max_new_tokens nearby.
  - ns-aiml-122 (rules/ai_security.yaml, regex presence): a retry wrapper
    (@retry/@tenacity.retry, or a same-line `except ...: continue`) with no
    visible attempt-cap term nearby.

The three ns-aiml-* rules are tested directly against NeuroScanRule.check()
(the native regex engine), matching this project's established convention
for regex-mode presence rules (see test_ns_aiml_109_markdown_exfil.py,
test_ns_aiml_110_reflection_dispatch.py) -- these fixtures exercise the
`sanitizers:` window mechanism directly rather than the opengrep-converted
production path, which is the same path this project's own test suite for
this rule shape already relies on.

TNT-ML-022 is tested via OpengrepAdapter.scan_with_rules, matching
test_agent_memory_write_taint.py's convention for taint-mode rules;
skipped entirely if the Opengrep binary isn't installed.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"


# ---------------------------------------------------------------------------
# TNT-ML-022 (ml_taint.yaml) -- taint rule
# ---------------------------------------------------------------------------

_adapter = OpengrepAdapter()
pytestmark_taint = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan_taint(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / "ml_taint.yaml"], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


@pytest.mark.skipif(not _adapter.is_installed(), reason="Opengrep binary not installed.")
class TestTntMl022UserControlledGenerationParams:
    def test_user_controlled_n_and_max_tokens_flagged(self, tmp_path):
        src = (
            "def generate():\n"
            "    n_val = request.json['n']\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        n=int(n_val),\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_n.py", src, "TNT-ML-022")
        assert findings, "request.json-derived value into n= must be flagged"

    def test_user_controlled_max_tokens_flagged(self, tmp_path):
        src = (
            "def generate():\n"
            "    mt_val = request.json['max_tokens']\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        max_tokens=int(mt_val),\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_mt.py", src, "TNT-ML-022")
        assert findings, "request.json-derived value into max_tokens= must be flagged"

    def test_int_cast_alone_is_not_a_sanitizer(self, tmp_path):
        # DEF-5 sanitizer-specificity review: int()/float() casting is
        # deliberately NOT in this rule's pattern-sanitizers -- it narrows
        # syntax, not magnitude, so the finding must still fire.
        src = (
            "def generate():\n"
            "    mt_val = int(request.json['max_tokens'])\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        max_tokens=mt_val,\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_int_cast.py", src, "TNT-ML-022")
        assert findings, "int() casting alone must not suppress -- it doesn't bound magnitude"

    def test_clamped_max_tokens_not_flagged(self, tmp_path):
        # Acceptance criterion: clamped max_tokens is clean.
        src = (
            "def generate():\n"
            "    mt_val = request.json['max_tokens']\n"
            "    mt_val = min(int(mt_val), 2048)\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        max_tokens=mt_val,\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_clamped.py", src, "TNT-ML-022")
        assert not findings, "min(x, LIMIT)-clamped max_tokens must not be flagged"

    def test_anthropic_messages_create_flagged(self, tmp_path):
        src = (
            "def generate():\n"
            "    mt_val = request.json['max_tokens']\n"
            "    return client.messages.create(\n"
            "        model='claude-3',\n"
            "        messages=msgs,\n"
            "        max_tokens=int(mt_val),\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_anthropic.py", src, "TNT-ML-022")
        assert findings, "request-derived value into Anthropic messages.create(max_tokens=) must be flagged"

    def test_litellm_completion_n_flagged(self, tmp_path):
        src = (
            "def generate():\n"
            "    n_val = request.json['n']\n"
            "    return litellm.completion(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        n=int(n_val),\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_litellm.py", src, "TNT-ML-022")
        assert findings, "request-derived value into litellm.completion(n=) must be flagged"

    def test_hardcoded_max_tokens_not_flagged(self, tmp_path):
        src = (
            "def generate():\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        max_tokens=512,\n"
            "    )\n"
        )
        findings = _scan_taint(tmp_path, "gen_hardcoded.py", src, "TNT-ML-022")
        assert not findings, "a hardcoded max_tokens with no request-derived source must not be flagged"


# ---------------------------------------------------------------------------
# ns-aiml-120 -- unbounded while-True loop
# ---------------------------------------------------------------------------


def _rule(rule_id):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestNsAiml120UnboundedLoop:
    def test_model_terminated_loop_flagged(self, tmp_path):
        # Acceptance criterion: model-terminated loop is a finding. The
        # "if DONE in reply: break" idiom is still unbounded -- termination
        # must be code-controlled, not model-controlled.
        fp = tmp_path / "reflection_loop.py"
        fp.write_text(
            "while True:\n"
            "    reply = client.messages.create(model='claude-3', messages=msgs)\n"
            "    if 'DONE' in reply.content[0].text:\n"
            "        break\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-120").check(fp), (
            "while True: with only a model-decided break condition must be flagged"
        )

    def test_bounded_agent_loop_not_flagged(self, tmp_path):
        # Acceptance criterion: bounded agent loop is clean.
        fp = tmp_path / "bounded_loop.py"
        fp.write_text(
            "max_iterations = 10\n"
            "i = 0\n"
            "while True:\n"
            "    reply = client.messages.create(model='claude-3', messages=msgs)\n"
            "    i += 1\n"
            "    if i >= max_iterations:\n"
            "        break\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-120").check(fp) == [], (
            "a while True: loop with a max_iterations-bounded counter nearby must not be flagged"
        )

    def test_deadline_bounded_loop_not_flagged(self, tmp_path):
        fp = tmp_path / "deadline_loop.py"
        fp.write_text(
            "deadline = time.time() + 30\n"
            "while True:\n"
            "    reply = client.messages.create(model='claude-3', messages=msgs)\n"
            "    if time.time() > deadline:\n"
            "        break\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-120").check(fp) == [], (
            "a while True: loop with a wall-clock deadline check nearby must not be flagged"
        )

    def test_langgraph_recursion_limit_not_flagged(self, tmp_path):
        fp = tmp_path / "langgraph_agent.py"
        fp.write_text(
            "graph.invoke(state, config={'recursion_limit': 25})\n"
            "while True:\n"
            "    step()\n"
            "    if done:\n"
            "        break\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-120").check(fp) == [], (
            "recursion_limit configured nearby must suppress the signal"
        )

    def test_comment_only_mention_not_flagged(self, tmp_path):
        fp = tmp_path / "notes.py"
        fp.write_text(
            "# TODO: replace with while True: loop once we add pagination\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-120").check(fp) == [], "a commented-out mention must not be flagged"


# ---------------------------------------------------------------------------
# ns-aiml-121 -- completion call with no max_tokens
# ---------------------------------------------------------------------------


class TestNsAiml121NoMaxTokens:
    def test_route_handler_without_max_tokens_flagged(self, tmp_path):
        fp = tmp_path / "generate_endpoint.py"
        fp.write_text(
            "@app.post('/generate')\n"
            "def generate():\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "    )\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-121").check(fp), (
            "a completion call with no max_tokens/max_completion_tokens nearby must be flagged"
        )

    def test_max_tokens_present_not_flagged(self, tmp_path):
        fp = tmp_path / "generate_capped.py"
        fp.write_text(
            "@app.post('/generate')\n"
            "def generate():\n"
            "    return client.chat.completions.create(\n"
            "        model='gpt-4o',\n"
            "        messages=msgs,\n"
            "        max_tokens=512,\n"
            "    )\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-121").check(fp) == [], (
            "max_tokens present nearby must suppress the signal"
        )

    def test_max_completion_tokens_present_not_flagged(self, tmp_path):
        fp = tmp_path / "generate_capped2.py"
        fp.write_text(
            "def generate():\n"
            "    return client.chat.completions.create(\n"
            "        model='o1',\n"
            "        messages=msgs,\n"
            "        max_completion_tokens=1024,\n"
            "    )\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-121").check(fp) == [], (
            "max_completion_tokens present nearby must suppress the signal"
        )


# ---------------------------------------------------------------------------
# ns-aiml-122 -- retry wrapper with no attempt cap
# ---------------------------------------------------------------------------


class TestNsAiml122RetryNoCap:
    def test_uncapped_tenacity_retry_flagged(self, tmp_path):
        fp = tmp_path / "retry_uncapped.py"
        fp.write_text(
            "@tenacity.retry(wait=wait_exponential())\n"
            "def call_llm():\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=msgs)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-122").check(fp), (
            "a @tenacity.retry(...) with no stop= nearby must be flagged"
        )

    def test_capped_tenacity_retry_not_flagged(self, tmp_path):
        fp = tmp_path / "retry_capped.py"
        fp.write_text(
            "@tenacity.retry(\n"
            "    wait=wait_exponential(),\n"
            "    stop=stop_after_attempt(5),\n"
            ")\n"
            "def call_llm():\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=msgs)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-122").check(fp) == [], (
            "stop=stop_after_attempt(...) nearby (even on a later line of a "
            "multi-line decorator) must suppress the signal"
        )

    def test_bare_retry_decorator_flagged(self, tmp_path):
        fp = tmp_path / "retry_bare.py"
        fp.write_text(
            "@retry\n"
            "def call_llm():\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=msgs)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-122").check(fp), "a bare @retry with no cap nearby must be flagged"

    def test_except_continue_retry_loop_flagged(self, tmp_path):
        fp = tmp_path / "retry_while.py"
        fp.write_text(
            "def call_llm():\n"
            "    while True:\n"
            "        try:\n"
            "            return client.chat.completions.create(model='gpt-4o', messages=msgs)\n"
            "        except RateLimitError: continue\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-122").check(fp), (
            "a same-line 'except ...: continue' retry idiom with no attempt cap must be flagged"
        )

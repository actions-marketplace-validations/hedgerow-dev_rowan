"""LLM cache tenancy (issue #192, epic #183).

ns-aiml-111 gets agent-memory tenancy right (a memory write with no visible
user_id/namespace is flagged); semantic/response caches have the identical
bug and were uncovered -- zero corpus hits for gptcache, set_llm_cache,
RedisSemanticCache, langchain.cache, semantic_cache before this.

  ns-aiml-152  LLM cache configured without a tenant-scoped key. Same
               tenant-term recognizer as ns-aiml-111 (widened here to the
               same four-term canonical set: user_id/namespace/session_id/
               tenant), mirrored rather than reinvented.
  ns-aiml-153  semantic cache similarity threshold not set. Presence
               signal only -- does not judge whether a SET threshold is an
               appropriate value.
  TNT-ML-031   untrusted input reaching a cache write that a later read
               serves (poisoning flow), modeled the same same-function
               write-then-read shape as TNT-PATH-003.

Also verifies: Anthropic-style cache_control blocks (provider-side prompt
caching, not a cross-tenant risk) are not flagged by any of the above, and
ns-aiml-111 still fires/stays-quiet correctly after its tenant-term set was
widened to match ns-aiml-152's.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULES_PATH = RULES_DIR / "ai_security.yaml"
CONVERTED_RULES_PATH = RULES_DIR / "converted" / "ai_security.yaml"
ML_TAINT_PATH = RULES_DIR / "ml_taint.yaml"
_RULES = load_neuroscan_rules(RULES_PATH)

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _scan_converted(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [CONVERTED_RULES_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


def _scan_taint(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [ML_TAINT_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id]


class TestNsAiml152CacheTenantKey:
    def test_redis_semantic_cache_no_tenant_term_flagged(self, tmp_path):
        src = (
            "set_llm_cache(RedisSemanticCache(redis_url='redis://localhost:6379', embedding=embeddings))\n"
        )
        assert _scan(tmp_path, "cache_setup.py", src, "ns-aiml-152")
        assert _scan_converted(tmp_path, "cache_setup.py", src, "ns-aiml-152")

    def test_gptcache_keyed_on_prompt_only_flagged(self, tmp_path):
        src = (
            "cache = GPTCache()\n"
            "cache.init(pre_embedding_func=get_prompt)\n"
        )
        assert _scan(tmp_path, "gptcache_setup.py", src, "ns-aiml-152")
        assert _scan_converted(tmp_path, "gptcache_setup.py", src, "ns-aiml-152")

    def test_litellm_cache_no_tenant_term_flagged(self, tmp_path):
        src = "litellm.cache = Cache(type='redis', host='localhost', port=6379)\n"
        assert _scan(tmp_path, "litellm_cache.py", src, "ns-aiml-152")
        assert _scan_converted(tmp_path, "litellm_cache.py", src, "ns-aiml-152")

    def test_cache_with_user_id_key_not_flagged(self, tmp_path):
        src = (
            "cache = GPTCache()\n"
            "cache.init(pre_embedding_func=get_prompt, user_id=current_user_id)\n"
        )
        assert _scan(tmp_path, "gptcache_safe.py", src, "ns-aiml-152") == []
        assert _scan_converted(tmp_path, "gptcache_safe.py", src, "ns-aiml-152") == []

    def test_cache_with_tenant_namespace_not_flagged(self, tmp_path):
        src = (
            "set_llm_cache(\n"
            "    RedisSemanticCache(redis_url='redis://localhost:6379', embedding=embeddings, namespace=tenant_id)\n"
            ")\n"
        )
        assert _scan(tmp_path, "cache_scoped.py", src, "ns-aiml-152") == []
        assert _scan_converted(tmp_path, "cache_scoped.py", src, "ns-aiml-152") == []

    def test_anthropic_cache_control_not_flagged(self, tmp_path):
        """Item 4: provider-side prompt caching is not a cross-tenant risk."""
        src = (
            "messages = [{\n"
            "    'role': 'user',\n"
            "    'content': [{'type': 'text', 'text': big_doc, 'cache_control': {'type': 'ephemeral'}}],\n"
            "}]\n"
        )
        assert _scan(tmp_path, "anthropic_caching.py", src, "ns-aiml-152") == []
        assert _scan_converted(tmp_path, "anthropic_caching.py", src, "ns-aiml-152") == []
        assert _scan(tmp_path, "anthropic_caching.py", src, "ns-aiml-153") == []
        assert _scan_converted(tmp_path, "anthropic_caching.py", src, "ns-aiml-153") == []


class TestNsAiml153SimilarityThreshold:
    def test_redis_semantic_cache_no_threshold_flagged(self, tmp_path):
        src = "cache = RedisSemanticCache(redis_url='redis://localhost:6379', embedding=embeddings)\n"
        assert _scan(tmp_path, "sem_cache.py", src, "ns-aiml-153")
        assert _scan_converted(tmp_path, "sem_cache.py", src, "ns-aiml-153")

    def test_gptcache_no_threshold_flagged(self, tmp_path):
        src = "cache = GPTCache()\ncache.init(similarity_evaluation=SearchDistanceEvaluation())\n"
        assert _scan(tmp_path, "gptcache_no_thresh.py", src, "ns-aiml-153")
        assert _scan_converted(tmp_path, "gptcache_no_thresh.py", src, "ns-aiml-153")

    def test_explicit_similarity_threshold_not_flagged(self, tmp_path):
        src = (
            "cache = RedisSemanticCache(\n"
            "    redis_url='redis://localhost:6379', embedding=embeddings, similarity_threshold=0.9\n"
            ")\n"
        )
        assert _scan(tmp_path, "sem_cache_safe.py", src, "ns-aiml-153") == []
        assert _scan_converted(tmp_path, "sem_cache_safe.py", src, "ns-aiml-153") == []


class TestTntMl031CachePoisoning:
    def test_untrusted_prompt_into_cache_write_then_read_flagged(self, tmp_path):
        src = (
            "def warm_cache():\n"
            "    prompt = request.json.get('prompt')\n"
            "    cache.put(prompt, generate_response(prompt))\n"
            "    return cache.get(prompt)\n"
        )
        assert _scan_taint(tmp_path, "cache_poison.py", src, "TNT-ML-031")

    def test_untrusted_key_into_cache_set_then_get_flagged(self, tmp_path):
        src = (
            "def warm_cache():\n"
            "    key = request.json.get('key')\n"
            "    cache.set(key, generate_response(key))\n"
            "    return cache.get(key)\n"
        )
        assert _scan_taint(tmp_path, "cache_poison2.py", src, "TNT-ML-031")

    def test_untrusted_value_only_not_flagged(self, tmp_path):
        """Documented accepted false-negative gap (see the rule's own engine
        note): attacker controls only the cached VALUE under an
        otherwise-benign, non-tainted KEY. Verified empirically that
        Opengrep's propagator to: binding does not compose with this rule's
        necessary metavariable-regex-constrained sink -- not a rule this
        engine can express without reopening the reflexive false-positive
        the constraint exists to prevent."""
        src = (
            "def warm_cache(key):\n"
            "    response = request.json.get('response')\n"
            "    cache.set(key, response)\n"
            "    return cache.get(key)\n"
        )
        assert _scan_taint(tmp_path, "cache_value_only.py", src, "TNT-ML-031") == []

    def test_no_cache_read_not_flagged(self, tmp_path):
        src = (
            "def warm_cache():\n"
            "    prompt = request.json.get('prompt')\n"
            "    cache.put(prompt, generate_response(prompt))\n"
        )
        assert _scan_taint(tmp_path, "cache_write_only.py", src, "TNT-ML-031") == []

    def test_hardcoded_cache_entry_not_flagged(self, tmp_path):
        src = (
            "def warm_cache():\n"
            "    cache.put('static-key', 'static-value')\n"
            "    return cache.get('static-key')\n"
        )
        assert _scan_taint(tmp_path, "cache_static.py", src, "TNT-ML-031") == []


class TestNsAiml111WidenedTenantTerms:
    """Regression: ns-aiml-111's tenant-term set was widened to match
    ns-aiml-152's canonical four terms; must still fire on the original
    unscoped case and stay quiet on user_id (already covered) AND the
    newly added session_id/tenant terms, on both engines."""

    def test_unscoped_memory_add_still_flagged(self, tmp_path):
        src = "memory = Memory()\nmemory.add(user_message, agent_id='a1')\n"
        assert _scan(tmp_path, "mem_unscoped.py", src, "ns-aiml-111")
        assert _scan_converted(tmp_path, "mem_unscoped.py", src, "ns-aiml-111")

    def test_session_id_scoped_not_flagged(self, tmp_path):
        src = "memory = Memory()\nmemory.add(user_message, session_id=sid)\n"
        assert _scan(tmp_path, "mem_session.py", src, "ns-aiml-111") == []
        assert _scan_converted(tmp_path, "mem_session.py", src, "ns-aiml-111") == []

    def test_tenant_scoped_not_flagged(self, tmp_path):
        src = "memory = Memory()\nmemory.add(user_message, tenant_id=tid)\n"
        assert _scan(tmp_path, "mem_tenant.py", src, "ns-aiml-111") == []
        assert _scan_converted(tmp_path, "mem_tenant.py", src, "ns-aiml-111") == []

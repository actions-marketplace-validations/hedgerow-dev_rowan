"""Positive/negative fixtures for TNT-ML-026 / TNT-ML-027
(rules/ml_taint.yaml, issue #292: vector-store / RediSearch query-DSL
injection, CVE-2026-27022 class).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see
.github/workflows/ci.yml).

These two rules EXTEND TNT-ML-020/021 (Weaviate GraphQL + generic
filter-dict injection, issue #138) into the query-string DSL surface, and
their sinks are deliberately disjoint from those (BACKLOG.md DEF-15/19
(file,line)-overlap method). Each rule therefore carries a control that
asserts (a) it does not fire on TNT-ML-020/021's own fixtures, and (b)
TNT-ML-020/021 do not fire on its fixtures -- so no single (file,line) is
claimed by both families.

Rule split (see the rules' own engine notes in rules/ml_taint.yaml):
  - TNT-ML-026 (multi-language: python + javascript + typescript): a
    request value interpolated into a RediSearch query STRING reaching
    `.ft(...).search(...)` (redis-py), node-redis `.ft.search`, a raw
    `FT.SEARCH`/`FT.AGGREGATE` command, or redisvl `FilterQuery(...)`. The
    CVE-2026-27022 case shipped in JS.
  - TNT-ML-027 (python-only, by opengrep engine limitation documented in
    the rule): a request value concatenated/f-stringed into a Pinecone /
    Qdrant / LangChain-retriever metadata-filter STRING. A structured
    filter dict carrying request values in its VALUES is the safe path and
    must NOT fire.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "ml_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id, languages=("python",)):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=list(languages)
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestRediSearchDSLInjectionTNTML026:
    """TNT-ML-026: request source -> RediSearch query DSL string."""

    def test_redispy_ft_search_fstring_flagged(self, tmp_path):
        src = (
            "def search(r):\n"
            "    uid = request.args.get('user')\n"
            "    q = f\"@user:{{{uid}}}\"\n"
            "    return r.ft('idx').search(q)\n"
        )
        findings = _scan(tmp_path, "redispy.py", src, "TNT-ML-026")
        assert findings, "f-string RediSearch query into r.ft(idx).search() must be flagged"

    def test_redispy_execute_command_ft_search_flagged(self, tmp_path):
        src = (
            "def search(store):\n"
            "    term = request.args.get('term')\n"
            "    return store.execute_command('FT.SEARCH', 'idx', f'@body:{term}')\n"
        )
        findings = _scan(tmp_path, "redis_execcmd.py", src, "TNT-ML-026")
        assert findings, "request value into a raw FT.SEARCH execute_command() must be flagged"

    def test_redisvl_filterquery_flagged(self, tmp_path):
        src = (
            "def search(index):\n"
            "    raw = request.args.get('f')\n"
            "    fq = FilterQuery(f'@tag:{{{raw}}}')\n"
            "    return index.query(fq)\n"
        )
        findings = _scan(tmp_path, "redisvl.py", src, "TNT-ML-026")
        assert findings, "request value f-stringed into redisvl FilterQuery() must be flagged"

    def test_node_redis_ft_search_flagged_js(self, tmp_path):
        # CVE-2026-27022 shape: node-redis client.ft.search with an
        # interpolated query. Different client wrapper AND different
        # variable names from the Python fixtures -- proves the rule
        # generalizes, it is not pinned to one library's call.
        src = (
            "async function searchNode(client, req) {\n"
            "  const uid = req.query.user;\n"
            "  const q = `@user:{${uid}}`;\n"
            "  return await client.ft.search('idx', q);\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "redis.js", src, "TNT-ML-026", languages=("javascript",)
        )
        assert findings, "node-redis client.ft.search() with an interpolated query must be flagged (CVE-2026-27022)"

    def test_ioredis_call_ft_search_flagged_ts(self, tmp_path):
        src = (
            "async function q(redis: any, req: any) {\n"
            "  const term = req.params.term;\n"
            "  return await redis.call('FT.SEARCH', 'idx', `@body:${term}`);\n"
            "}\n"
        )
        findings = _scan(
            tmp_path, "redis.ts", src, "TNT-ML-026", languages=("typescript",)
        )
        assert findings, "ioredis redis.call('FT.SEARCH', ...) with an interpolated query must be flagged"

    def test_numeric_coercion_not_flagged(self, tmp_path):
        src = (
            "def search(r):\n"
            "    n = int(request.args.get('n'))\n"
            "    return r.ft('idx').search(f'@price:[{n} {n}]')\n"
        )
        findings = _scan(tmp_path, "redis_numeric.py", src, "TNT-ML-026")
        assert findings == [], (
            "a numerically coerced value (int()) into a RediSearch query is bounded and must not be flagged"
        )

    def test_redisvl_tag_builder_not_flagged(self, tmp_path):
        src = (
            "def search(index):\n"
            "    uid = request.args.get('user')\n"
            "    fq = FilterQuery(Tag('user') == uid)\n"
            "    return index.query(fq)\n"
        )
        findings = _scan(tmp_path, "redisvl_tag.py", src, "TNT-ML-026")
        assert findings == [], (
            "redisvl's escaping filter builder (Tag(field) == value) is the parameterized safe path and must not be flagged"
        )


class TestMetadataFilterStringInjectionTNTML027:
    """TNT-ML-027: request source -> vector-store metadata-filter STRING."""

    def test_similarity_search_fstring_filter_flagged(self, tmp_path):
        src = (
            "def search(vectorstore):\n"
            "    genre = request.args.get('genre')\n"
            "    return vectorstore.similarity_search('q', filter=f\"genre == '{genre}'\")\n"
        )
        findings = _scan(tmp_path, "pinecone_str.py", src, "TNT-ML-027")
        assert findings, "an f-string metadata filter into similarity_search(filter=) must be flagged"

    def test_mmr_concat_filter_diff_wrapper_flagged(self, tmp_path):
        # Different retrieval method, different wrapper receiver name, and
        # string concatenation rather than an f-string -- proves the rule
        # generalizes beyond the original PoC shape.
        src = (
            "def search(store):\n"
            "    username = request.json['user']\n"
            "    return store.max_marginal_relevance_search('q', k=5, filter=\"user == '\" + username + \"'\")\n"
        )
        findings = _scan(tmp_path, "mmr_concat.py", src, "TNT-ML-027")
        assert findings, "a concatenated metadata filter into max_marginal_relevance_search(filter=) must be flagged"

    def test_qdrant_scroll_filter_string_flagged(self, tmp_path):
        src = (
            "def search(client):\n"
            "    cond = request.args.get('cond')\n"
            "    return client.scroll(collection_name='docs', scroll_filter=f\"city == '{cond}'\")\n"
        )
        findings = _scan(tmp_path, "qdrant_scroll.py", src, "TNT-ML-027")
        assert findings, "a request value f-stringed into Qdrant scroll_filter= must be flagged"

    def test_structured_dict_value_taint_not_flagged(self, tmp_path):
        # The safe path the issue calls out: a structured filter dict with a
        # request value only in the VALUE position. Must NOT fire -- this is
        # the precision distinction TNT-ML-027 adds over TNT-ML-020.
        src = (
            "def search(vectorstore):\n"
            "    genre = request.args.get('genre')\n"
            "    return vectorstore.similarity_search('q', filter={'genre': {'$eq': genre}})\n"
        )
        findings = _scan(tmp_path, "pinecone_dict.py", src, "TNT-ML-027")
        assert findings == [], (
            "a structured filter dict with the request value in its value position is the safe path and must not be flagged"
        )

    def test_assigned_fstring_filter_flagged(self, tmp_path):
        # The dominant real-world shape: the filter STRING is built into a
        # variable first, then passed as filter=flt. The string-shape gate must
        # follow the assignment, not only match an inline literal at the call.
        src = (
            "def search(vectorstore):\n"
            "    genre = request.args.get('genre')\n"
            "    flt = f\"genre == '{genre}'\"\n"
            "    return vectorstore.similarity_search('q', filter=flt)\n"
        )
        findings = _scan(tmp_path, "assigned_fstring.py", src, "TNT-ML-027")
        assert findings, (
            "an f-string filter assigned to a variable then passed as filter= must be flagged"
        )

    def test_assigned_dict_filter_not_flagged(self, tmp_path):
        # Same assigned shape but a structured dict, not a string. Must NOT fire:
        # the assignment gate matches only string-DSL expressions, so the safe
        # structured-filter path stays clean even when held in a variable.
        src = (
            "def search(vectorstore):\n"
            "    genre = request.args.get('genre')\n"
            "    flt = {'genre': {'$eq': genre}}\n"
            "    return vectorstore.similarity_search('q', filter=flt)\n"
        )
        findings = _scan(tmp_path, "assigned_dict.py", src, "TNT-ML-027")
        assert findings == [], (
            "a structured filter dict held in a variable is the safe path and must not be flagged"
        )

    def test_pydantic_validated_filter_not_flagged(self, tmp_path):
        src = (
            "def search(vectorstore):\n"
            "    raw = request.json.get('filter')\n"
            "    flt = FilterModel.model_validate(raw)\n"
            "    return vectorstore.similarity_search('q', filter=flt)\n"
        )
        findings = _scan(tmp_path, "pinecone_validated.py", src, "TNT-ML-027")
        assert findings == [], (
            "a filter run through a Pydantic model_validate() sanitizer must not be flagged"
        )


class TestDisjointnessFromTNTML020021:
    """Sinks are disjoint from TNT-ML-020/021 (BACKLOG.md DEF-15/19 method):
    neither family may claim a (file,line) the other does."""

    _PINECONE_020 = (
        "def search(index, emb):\n"
        "    flt = json.loads(request.args['filter'])\n"
        "    return index.query(vector=emb, filter=flt, top_k=5)\n"
    )
    _WEAVIATE_021 = (
        "def search(client):\n"
        "    q = request.args.get('gql')\n"
        "    return client.query.raw(q)\n"
    )
    _REDISEARCH_026 = (
        "def search(r):\n"
        "    uid = request.args.get('user')\n"
        "    return r.ft('idx').search(f'@user:{uid}')\n"
    )
    _FILTERSTR_027 = (
        "def search(vectorstore):\n"
        "    genre = request.args.get('genre')\n"
        "    return vectorstore.similarity_search('q', filter=f\"genre == '{genre}'\")\n"
    )

    def test_020_fixture_control_unchanged(self, tmp_path):
        # TNT-ML-020 still fires on its own fixture; 026/027 stay silent.
        assert _scan(tmp_path, "p020.py", self._PINECONE_020, "TNT-ML-020"), (
            "control: TNT-ML-020 must still fire on the Pinecone filter-dict fixture"
        )
        assert _scan(tmp_path, "p020.py", self._PINECONE_020, "TNT-ML-026") == []
        assert _scan(tmp_path, "p020.py", self._PINECONE_020, "TNT-ML-027") == []

    def test_021_fixture_control_unchanged(self, tmp_path):
        assert _scan(tmp_path, "w021.py", self._WEAVIATE_021, "TNT-ML-021"), (
            "control: TNT-ML-021 must still fire on the Weaviate raw-GraphQL fixture"
        )
        assert _scan(tmp_path, "w021.py", self._WEAVIATE_021, "TNT-ML-026") == []
        assert _scan(tmp_path, "w021.py", self._WEAVIATE_021, "TNT-ML-027") == []

    def test_026_fixture_not_claimed_by_020_or_021(self, tmp_path):
        assert _scan(tmp_path, "r026.py", self._REDISEARCH_026, "TNT-ML-026"), (
            "TNT-ML-026 must fire on its own RediSearch fixture"
        )
        assert _scan(tmp_path, "r026.py", self._REDISEARCH_026, "TNT-ML-020") == []
        assert _scan(tmp_path, "r026.py", self._REDISEARCH_026, "TNT-ML-021") == []

    def test_027_fixture_not_claimed_by_020_or_021(self, tmp_path):
        assert _scan(tmp_path, "f027.py", self._FILTERSTR_027, "TNT-ML-027"), (
            "TNT-ML-027 must fire on its own filter-string fixture"
        )
        assert _scan(tmp_path, "f027.py", self._FILTERSTR_027, "TNT-ML-020") == []
        assert _scan(tmp_path, "f027.py", self._FILTERSTR_027, "TNT-ML-021") == []

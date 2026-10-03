"""Tests for ns-aiml-118 / ns-aiml-119 (rules/ai_security.yaml): multi-tenant
RAG isolation and pgvector inline-interpolation presence signals (issue #138).

  - ns-aiml-118: vector-store query call missing namespace=/filter=/where=/
    query_filter=/tenant/user_id scoping (Pinecone, Chroma, a generic
    LangChain-style vectorstore, Qdrant).
  - ns-aiml-119: a SQL string containing a pgvector distance operator
    (<->/<=>/<#>) built via f-string/.format()/%-format/concatenation
    instead of a parameterized query.

Companions to TNT-ML-020/021 (rules/ml_taint.yaml, tests in
tests/test_vector_filter_injection_taint.py) which model the taint-flow
shape of the same threat (issue #138's cross-tenant retrieval / metadata
filter injection).
"""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestNsAiml113MissingScoping:
    # ── Pinecone ──────────────────────────────────────────────────
    def test_pinecone_index_query_no_scoping_flagged(self, tmp_path):
        fp = tmp_path / "pinecone_search.py"
        fp.write_text(
            "def search(q, emb):\n"
            "    index = pinecone.Index('docs')\n"
            "    return index.query(vector=emb, top_k=5)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp), (
            "pinecone index.query() with no namespace=/filter= must be flagged"
        )

    def test_pinecone_index_query_with_namespace_and_filter_not_flagged(self, tmp_path):
        fp = tmp_path / "pinecone_scoped.py"
        fp.write_text(
            "def search(q, emb, g):\n"
            "    index = pinecone.Index('docs')\n"
            "    return index.query(vector=emb, filter={'tenant': {'$eq': g.tenant_id}}, namespace=g.tenant_id, top_k=5)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp) == [], (
            "pinecone index.query() with filter= and namespace= must not be flagged"
        )

    # ── Chroma ────────────────────────────────────────────────────
    def test_chroma_collection_query_no_scoping_flagged(self, tmp_path):
        fp = tmp_path / "chroma_search.py"
        fp.write_text(
            "def search():\n"
            "    return collection.query(query_texts=[request.args.get('q')])\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp), (
            "chroma collection.query() with no where= must be flagged"
        )

    def test_chroma_collection_query_with_where_not_flagged(self, tmp_path):
        fp = tmp_path / "chroma_scoped.py"
        fp.write_text(
            "def search(user_id):\n"
            "    return collection.query(query_texts=['q'], where={'user_id': user_id})\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp) == [], (
            "chroma collection.query() with where= must not be flagged"
        )

    # ── Generic LangChain-style vectorstore ──────────────────────
    def test_similarity_search_no_scoping_flagged(self, tmp_path):
        fp = tmp_path / "vectorstore_search.py"
        fp.write_text(
            "def search(vectorstore, q):\n"
            "    return vectorstore.similarity_search(q)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp), (
            "vectorstore.similarity_search() with no filter= must be flagged"
        )

    def test_similarity_search_with_filter_not_flagged(self, tmp_path):
        fp = tmp_path / "vectorstore_scoped.py"
        fp.write_text(
            "def search(vectorstore, q, tenant_id):\n"
            "    return vectorstore.similarity_search(q, filter={'tenant': tenant_id})\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp) == [], (
            "vectorstore.similarity_search() with filter= must not be flagged"
        )

    # ── Qdrant ────────────────────────────────────────────────────
    def test_qdrant_search_no_scoping_flagged(self, tmp_path):
        fp = tmp_path / "qdrant_search.py"
        fp.write_text(
            "def search(client, vec):\n"
            "    return client.search(collection_name='docs', query_vector=vec)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp), (
            "qdrant client.search() with no query_filter= must be flagged"
        )

    def test_qdrant_search_with_query_filter_not_flagged(self, tmp_path):
        fp = tmp_path / "qdrant_scoped.py"
        fp.write_text(
            "def search(client, vec, tenant_id):\n"
            "    return client.search(collection_name='docs', query_vector=vec, query_filter=tenant_id)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp) == [], (
            "qdrant client.search() with query_filter= must not be flagged"
        )

    def test_unrelated_orm_query_not_flagged(self, tmp_path):
        """Regression guard against the generic-.query( collision class: a
        receiver name unrelated to index/pinecone/collection/chroma must not
        match."""
        fp = tmp_path / "orm.py"
        fp.write_text(
            "def get_users():\n"
            "    return db.session.query(User).all()\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-118").check(fp) == [], (
            "an unrelated ORM session.query() call must not be flagged"
        )


class TestNsAiml114PgvectorInterpolation:
    def test_fstring_l2_distance_flagged(self, tmp_path):
        fp = tmp_path / "pgvector_fstring.py"
        fp.write_text(
            "def search(cur, user_input, emb):\n"
            "    cur.execute(f\"SELECT * FROM docs WHERE body='{user_input}' ORDER BY embedding <-> '{emb}'\")\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-119").check(fp), (
            "f-string SQL containing the <-> pgvector operator must be flagged"
        )

    def test_percent_format_cosine_distance_flagged(self, tmp_path):
        fp = tmp_path / "pgvector_percent.py"
        fp.write_text(
            "def search(cur, emb):\n"
            "    cur.execute(\"SELECT * FROM docs ORDER BY embedding <=> '%s'\" % emb)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-119").check(fp), (
            "%-format SQL containing the <=> pgvector operator must be flagged"
        )

    def test_concat_inner_product_flagged(self, tmp_path):
        fp = tmp_path / "pgvector_concat.py"
        fp.write_text(
            "def search(cur, emb):\n"
            "    cur.execute(\"SELECT * FROM docs ORDER BY embedding <#> '\" + emb + \"'\")\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-119").check(fp), (
            "string-concatenated SQL containing the <#> pgvector operator must be flagged"
        )

    def test_parameterized_pgvector_query_not_flagged(self, tmp_path):
        fp = tmp_path / "pgvector_param.py"
        fp.write_text(
            "def search(cur, emb):\n"
            "    cur.execute(\"SELECT * FROM docs ORDER BY embedding <-> %s\", (emb,))\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-119").check(fp) == [], (
            "a parameterized pgvector query (placeholder + separate params tuple) must not be flagged"
        )

    def test_fstring_sql_without_pgvector_operator_not_flagged_by_this_rule(self, tmp_path):
        """An ordinary interpolated SQL query with no pgvector operator is
        NS-SQLI-001's territory, not this rule's."""
        fp = tmp_path / "generic_sqli.py"
        fp.write_text(
            "def search(cur, user_input):\n"
            "    cur.execute(f\"SELECT * FROM users WHERE name='{user_input}'\")\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-119").check(fp) == [], (
            "generic interpolated SQL with no pgvector operator must not be flagged by ns-aiml-119"
        )

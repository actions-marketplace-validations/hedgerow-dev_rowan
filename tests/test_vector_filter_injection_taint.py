"""Positive/negative fixtures for TNT-ML-020 / TNT-ML-021
(rules/ml_taint.yaml, issue #138: multi-tenant RAG isolation and
vector-store metadata filter injection).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).

Rule split (see the rules' own engine notes in rules/ml_taint.yaml for the
full rationale):
  - TNT-ML-020: a request-supplied value builds a vector-store
    filter/where/query_filter/expr expression (Pinecone, Chroma, Qdrant,
    Milvus) -- the NoSQL-injection of RAG stacks. Distinct from TNT-ML-004,
    which models the query TEXT (not the filter STRUCTURE) being tainted.
  - TNT-ML-021: a request-supplied value reaches a raw Weaviate GraphQL
    query (client.query.raw()) or a .with_where() filter -- extends
    ns-aiml-017 (auth-config-presence only) into injection territory.

Companion presence-signal tests for the read-path-isolation and
pgvector-inline-interpolation shapes this taint engine can't reach (missing
namespace=/filter=/tenant scoping; single-statement f-string SQL) live in
tests/test_ns_aiml_113_114_rag_isolation.py.
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


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestFilterStructureInjectionTNTML020:
    """TNT-ML-020: request source -> vector-store filter/where kwarg."""

    def test_pinecone_json_loads_filter_flagged(self, tmp_path):
        src = (
            "def search(index, emb):\n"
            "    flt = json.loads(request.args['filter'])\n"
            "    return index.query(vector=emb, filter=flt, top_k=5)\n"
        )
        findings = _scan(tmp_path, "pinecone_filter.py", src, "TNT-ML-020")
        assert findings, "json.loads(request.args[...]) into Pinecone filter= must be flagged"

    def test_chroma_where_from_request_flagged(self, tmp_path):
        src = (
            "def search(collection):\n"
            "    where = json.loads(request.json.get('where'))\n"
            "    return collection.query(query_texts=['q'], where=where)\n"
        )
        findings = _scan(tmp_path, "chroma_filter.py", src, "TNT-ML-020")
        assert findings, "request.json.get(...) into Chroma where= must be flagged"

    def test_qdrant_query_filter_from_request_flagged(self, tmp_path):
        src = (
            "def search(qdrant_client, vec):\n"
            "    query_filter = json.loads(request.args.get('filter'))\n"
            "    return qdrant_client.search(collection_name='docs', query_vector=vec, query_filter=query_filter)\n"
        )
        findings = _scan(tmp_path, "qdrant_filter.py", src, "TNT-ML-020")
        assert findings, "request.args.get(...) into Qdrant query_filter= must be flagged"

    def test_milvus_expr_from_request_flagged(self, tmp_path):
        src = (
            "def search(milvus_collection, vec):\n"
            "    expr = request.args.get('expr')\n"
            "    return milvus_collection.search(data=[vec], expr=expr)\n"
        )
        findings = _scan(tmp_path, "milvus_filter.py", src, "TNT-ML-020")
        assert findings, "request.args.get(...) into Milvus expr= must be flagged"

    def test_pinecone_filter_from_trusted_session_state_not_flagged(self, tmp_path):
        src = (
            "def search(index, emb, g):\n"
            "    return index.query(vector=emb, filter={'tenant': {'$eq': g.tenant_id}}, namespace=g.tenant_id, top_k=5)\n"
        )
        findings = _scan(tmp_path, "pinecone_clean.py", src, "TNT-ML-020")
        assert findings == [], (
            "a filter built from trusted session state (g.tenant_id), not request data, must not be flagged"
        )

    def test_pydantic_validated_filter_not_flagged(self, tmp_path):
        src = (
            "def search(index, emb):\n"
            "    raw = json.loads(request.args['filter'])\n"
            "    flt = FilterModel.model_validate(raw)\n"
            "    return index.query(vector=emb, filter=flt, top_k=5)\n"
        )
        findings = _scan(tmp_path, "pinecone_validated.py", src, "TNT-ML-020")
        assert findings == [], (
            "a filter run through a Pydantic model_validate() sanitizer must not be flagged"
        )


class TestWeaviateGraphQLInjectionTNTML021:
    """TNT-ML-021: request source -> raw GraphQL query / with_where()."""

    def test_raw_graphql_query_from_request_flagged(self, tmp_path):
        src = (
            "def search(client):\n"
            "    q = request.args.get('gql')\n"
            "    return client.query.raw(q)\n"
        )
        findings = _scan(tmp_path, "weaviate_raw.py", src, "TNT-ML-021")
        assert findings, "request.args.get(...) into client.query.raw() must be flagged"

    def test_with_where_from_request_json_flagged(self, tmp_path):
        src = (
            "def search(client):\n"
            "    where_filter = json.loads(request.json.get('where'))\n"
            "    return client.query.get('Document', ['text']).with_where(where_filter).do()\n"
        )
        findings = _scan(tmp_path, "weaviate_with_where.py", src, "TNT-ML-021")
        assert findings, "request.json.get(...) into .with_where() must be flagged"

    def test_with_where_from_trusted_constant_not_flagged(self, tmp_path):
        src = (
            "def search(client, g):\n"
            "    where_filter = {'path': ['tenant'], 'operator': 'Equal', 'valueText': g.tenant_id}\n"
            "    return client.query.get('Document', ['text']).with_where(where_filter).do()\n"
        )
        findings = _scan(tmp_path, "weaviate_clean.py", src, "TNT-ML-021")
        assert findings == [], (
            "a where-filter built from trusted session state, not request data, must not be flagged"
        )

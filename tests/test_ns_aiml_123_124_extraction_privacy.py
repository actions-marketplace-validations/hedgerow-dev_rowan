"""Tests for ns-aiml-123 / ns-aiml-124 (rules/ai_security.yaml): model
extraction / privacy surface presence signals (issue #140).

  - ns-aiml-123: logprobs=True / top_logprobs=N presence (model-extraction /
    membership-inference oracle, Carlini et al. 2024). Companion to
    TNT-ML-023 (rules/agent_taint.yaml) which is the dataflow-correct
    variant that actually confirms the response reaches a serialization
    sink -- see tests/test_logprob_extraction_taint.py.
  - ns-aiml-124: embeddings.create() on a route with no visible auth
    decorator/dependency nearby (embedding inversion, Morris et al.).
"""

from pathlib import Path

from rowan.core.rules import load_neuroscan_rules

RULES_DIR = Path(__file__).parent.parent / "rules"


def _rule(rule_id):
    rules = load_neuroscan_rules(RULES_DIR / "ai_security.yaml")
    return next(r for r in rules if r.metadata.id == rule_id)


class TestNsAiml123LogprobExposure:
    def test_logprobs_true_flagged(self, tmp_path):
        fp = tmp_path / "complete.py"
        fp.write_text(
            "@app.get('/complete')\n"
            "def complete():\n"
            "    r = client.chat.completions.create(model='gpt-4o', logprobs=True, top_logprobs=20)\n"
            "    return jsonify(r.model_dump())\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-123").check(fp), (
            "logprobs=True on a completion call must be flagged"
        )

    def test_top_logprobs_flagged(self, tmp_path):
        fp = tmp_path / "complete2.py"
        fp.write_text(
            "def complete():\n"
            "    r = client.chat.completions.create(model='gpt-4o', top_logprobs=5)\n"
            "    return jsonify(r.model_dump())\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-123").check(fp), "top_logprobs=N must be flagged"

    def test_internal_confidence_scoring_not_flagged(self, tmp_path):
        fp = tmp_path / "score_internal.py"
        fp.write_text(
            "def compute_confidence_score(prompt):\n"
            "    # internal use only -- not returned to the client\n"
            "    r = client.chat.completions.create(model='gpt-4o', logprobs=True)\n"
            "    return _confidence_score(r)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-123").check(fp) == [], (
            "a nearby 'internal use only' / 'not returned to the client' "
            "comment must suppress the signal"
        )

    def test_comment_only_mention_not_flagged(self, tmp_path):
        fp = tmp_path / "notes.py"
        fp.write_text(
            "# TODO: consider logprobs=True for scoring\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-123").check(fp) == [], "a commented-out mention must not be flagged"


class TestNsAiml124EmbeddingExposure:
    def test_embeddings_create_no_auth_flagged(self, tmp_path):
        fp = tmp_path / "embed.py"
        fp.write_text(
            "@app.post('/embed')\n"
            "def embed():\n"
            "    text = request.json.get('text')\n"
            "    r = client.embeddings.create(model='text-embedding-3-small', input=text)\n"
            "    return jsonify(r.data[0].embedding)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-124").check(fp), (
            "embeddings.create() on a route with no auth decorator nearby must be flagged"
        )

    def test_embeddings_create_with_login_required_not_flagged(self, tmp_path):
        fp = tmp_path / "embed_auth.py"
        fp.write_text(
            "@app.post('/embed')\n"
            "@login_required\n"
            "def embed():\n"
            "    text = request.json.get('text')\n"
            "    r = client.embeddings.create(model='text-embedding-3-small', input=text)\n"
            "    return jsonify(r.data[0].embedding)\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-124").check(fp) == [], (
            "@login_required nearby must suppress the signal"
        )

    def test_embeddings_create_with_fastapi_depends_not_flagged(self, tmp_path):
        fp = tmp_path / "embed_fastapi.py"
        fp.write_text(
            "@router.post('/embed')\n"
            "def embed(text: str, user=Depends(get_current_user)):\n"
            "    r = client.embeddings.create(model='text-embedding-3-small', input=text)\n"
            "    return {'embedding': r.data[0].embedding}\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-124").check(fp) == [], (
            "Depends(get_current_user) nearby must suppress the signal"
        )

    def test_comment_only_mention_not_flagged(self, tmp_path):
        fp = tmp_path / "notes.py"
        fp.write_text(
            "# TODO: wire up client.embeddings.create( for search\n",
            encoding="utf-8",
        )
        assert _rule("ns-aiml-124").check(fp) == [], "a commented-out mention must not be flagged"

"""Fixtures for TNT-ML-023 (rules/agent_taint.yaml): a logprob-enabled chat
completion response reaching a client-facing serialization sink (issue #140,
model-extraction / membership-inference surface -- Carlini et al. 2024).

Dataflow-correct companion to ns-aiml-123 (rules/ai_security.yaml), which is
a weaker presence-only signal that cannot enforce the "response actually
reaches a sink" requirement -- see that rule's own engine note.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it).
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


class TestLogprobResponseToClientFlagged:
    def test_logprobs_true_jsonify_model_dump_flagged(self, tmp_path):
        # The issue's own example.
        src = (
            "@app.get('/complete')\n"
            "def complete(client):\n"
            "    r = client.chat.completions.create(model='gpt-4o', logprobs=True, top_logprobs=20)\n"
            "    return jsonify(r.model_dump())\n"
        )
        findings = _scan(tmp_path, "complete.py", src, "TNT-ML-023")
        assert findings, "logprobs=True response reaching jsonify(r.model_dump()) must be flagged"

    def test_top_logprobs_direct_return_flagged(self, tmp_path):
        src = (
            "def complete(client):\n"
            "    resp = client.chat.completions.create(model='gpt-4o', top_logprobs=5)\n"
            "    return resp\n"
        )
        findings = _scan(tmp_path, "complete_return.py", src, "TNT-ML-023")
        assert findings, "top_logprobs response reaching a bare return must be flagged"

    def test_fastapi_jsonresponse_flagged(self, tmp_path):
        src = (
            "def complete(client):\n"
            "    resp = client.chat.completions.create(model='gpt-4o', logprobs=True)\n"
            "    return JSONResponse(resp)\n"
        )
        findings = _scan(tmp_path, "complete_fastapi.py", src, "TNT-ML-023")
        assert findings, "JSONResponse(resp) with logprobs enabled must be flagged"


class TestLogprobInternalOnlyNotFlagged:
    def test_logprobs_not_reaching_a_sink_not_flagged(self, tmp_path):
        # logprobs used for internal confidence scoring only -- never
        # serialized or returned to a caller.
        src = (
            "def compute_confidence(client, prompt):\n"
            "    resp = client.chat.completions.create(model='gpt-4o', logprobs=True)\n"
            "    avg_logprob = sum(t.logprob for t in resp.choices[0].logprobs.content) / len(resp.choices[0].logprobs.content)\n"
            "    _store_metric(avg_logprob)\n"
        )
        findings = _scan(tmp_path, "confidence_internal.py", src, "TNT-ML-023")
        assert not findings, (
            "a logprobs-enabled response that never reaches jsonify/model_dump/"
            "JSONResponse/return must not be flagged"
        )

    def test_no_logprobs_returned_not_flagged(self, tmp_path):
        src = (
            "def complete(client):\n"
            "    resp = client.chat.completions.create(model='gpt-4o')\n"
            "    return jsonify(resp.model_dump())\n"
        )
        findings = _scan(tmp_path, "complete_no_logprobs.py", src, "TNT-ML-023")
        assert not findings, "a completion without logprobs/top_logprobs must not be flagged"

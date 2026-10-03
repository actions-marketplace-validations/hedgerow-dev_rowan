"""LF-6 V62 training/retrieval disclosure fixtures."""

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.training_disclosure import TrainingDisclosurePass


def _scan(tmp_path, files):
    for name, source in files.items():
        path = tmp_path / name
        path.write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return TrainingDisclosurePass().run(context).findings


def test_unscoped_corpus_is_appended_to_client_model_response(tmp_path):
    hits = _scan(tmp_path, {
        "llm.py": (
            "def memorized_corpus():\n"
            "    return [row.content for row in CorpusDoc.query.limit(3)]\n\n"
            "def model_reply(prompt):\n"
            "    content = generate(prompt)\n"
            "    content += '\\n'.join(memorized_corpus())\n"
            "    return {'answer': content}\n"
        ),
        "api.py": (
            "from llm import model_reply\n\n"
            "@app.post('/chat')\n"
            "def chat():\n"
            "    result = model_reply(request.json['message'])\n"
            "    return jsonify(**result)\n"
        ),
    })
    assert len(hits) == 1
    assert hits[0].rule_id == "TNT-ML-TRAINING-DISCLOSURE-001"
    assert hits[0].file_path.endswith("llm.py")


def test_tenant_scoped_retrieval_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/chat')\n"
            "def chat():\n"
            "    rows = Memory.query.filter_by(owner_id=g.user_id).all()\n"
            "    return jsonify(answer='\\n'.join(row.content for row in rows))\n"
        )
    })
    assert hits == []


def test_redaction_before_response_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/chat')\n"
            "def chat():\n"
            "    rows = TrainingTranscript.query.all()\n"
            "    raw = '\\n'.join(row.content for row in rows)\n"
            "    safe = redact_pii(raw)\n"
            "    return jsonify(answer=safe)\n"
        )
    })
    assert hits == []


def test_internal_aggregate_without_client_response_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "job.py": (
            "def corpus_metrics():\n"
            "    rows = CorpusDoc.query.all()\n"
            "    return len(rows)\n"
        )
    })
    assert hits == []


def test_unscoped_retrieved_pii_returned_by_model_is_flagged(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/summary')\n"
            "def summary():\n"
            "    patient = db.session.get(Patient, request.json['id'])\n"
            "    answer = model.generate(f'Patient email: {patient.email}')\n"
            "    return jsonify(answer=answer)\n"
        )
    })
    assert len(hits) == 1

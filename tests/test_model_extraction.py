"""LF-6 V55 full probability-vector exposure fixtures."""

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.model_extraction import ModelExtractionPass


def _scan(tmp_path, files):
    for name, source in files.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return ModelExtractionPass().run(context).findings


def test_cross_file_full_probability_vector_is_flagged(tmp_path):
    hits = _scan(tmp_path, {
        "scorer.py": "def score(model, rows):\n    return model.predict_proba(rows)\n",
        "api.py": (
            "from scorer import score\n\n"
            "@app.post('/probabilities')\n"
            "def probabilities():\n"
            "    return jsonify(probabilities=score(model, request.json['rows']))\n"
        ),
    })
    assert len(hits) == 1
    assert hits[0].rule_id == "ML-MODEL-EXTRACTION-001"


def test_top_label_only_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/label')\n"
            "def label():\n"
            "    probabilities = model.predict_proba(request.json['rows'])\n"
            "    return jsonify(label=max(probabilities, key=probabilities.get))\n"
        )
    })
    assert hits == []


def test_bounded_top_k_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/top')\n"
            "def top():\n"
            "    probabilities = model.predict_proba(request.json['rows'])\n"
            "    reduced = sorted(probabilities.items(), reverse=True)[:3]\n"
            "    return jsonify(probabilities=reduced)\n"
        )
    })
    assert hits == []


def test_rate_limited_probability_endpoint_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/probabilities')\n"
            "@rate_limit('5/minute')\n"
            "def probabilities():\n"
            "    return jsonify(probabilities=model.predict_proba(request.json['rows']))\n"
        )
    })
    assert hits == []


def test_internal_probability_use_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "eval.py": "def evaluate(rows):\n    return model.predict_proba(rows)\n"
    })
    assert hits == []

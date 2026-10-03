"""LF-6 V56 per-record membership-signal fixtures."""

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.membership_inference import MembershipInferencePass


def _scan(tmp_path, files):
    for name, source in files.items():
        (tmp_path / name).write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return MembershipInferencePass().run(context).findings


def test_cross_file_per_record_loss_is_flagged(tmp_path):
    hits = _scan(tmp_path, {
        "metrics.py": "def score(model, row):\n    return model.record_loss(row)\n",
        "api.py": (
            "from metrics import score\n\n"
            "@app.get('/loss')\n"
            "def loss():\n"
            "    return jsonify(loss=score(model, request.args['row']))\n"
        ),
    })
    assert len(hits) == 1
    assert hits[0].rule_id == "ML-MEMBERSHIP-INFERENCE-001"


def test_per_sample_confidence_is_flagged(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/confidence')\n"
            "def confidence():\n"
            "    value = estimator.sample_confidence(request.json['features'])\n"
            "    return jsonify(confidence=value)\n"
        )
    })
    assert len(hits) == 1


def test_batch_loss_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/evaluation')\n"
            "def evaluation():\n"
            "    return jsonify(loss=model.batch_loss(request.json['rows']))\n"
        )
    })
    assert hits == []


def test_explicit_mean_reduction_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "api.py": (
            "@app.post('/evaluation')\n"
            "def evaluation():\n"
            "    losses = [model.record_loss(row) for row in request.json['rows']]\n"
            "    return jsonify(loss=statistics.mean(losses))\n"
        )
    })
    assert hits == []


def test_internal_per_record_metric_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "metrics.py": "def diagnostic(model, row):\n    return model.record_loss(row)\n"
    })
    assert hits == []


def test_mock_patch_decorated_function_is_not_a_route(tmp_path):
    hits = _scan(tmp_path, {
        "helpers.py": (
            "@mock.patch('os.path.exists')\n"
            "def check(exists):\n"
            "    return jsonify(loss=model.record_loss(row))\n"
        )
    })
    assert hits == []

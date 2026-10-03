"""Metamorphic checks that LF-6 behavior survives application-specific renaming."""

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.membership_inference import MembershipInferencePass
from rowan.passes.model_extraction import ModelExtractionPass
from rowan.passes.training_disclosure import TrainingDisclosurePass


def _run(tmp_path, source, pass_type):
    (tmp_path / "renamed.py").write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return pass_type().run(context).findings


def test_probability_vector_survives_renamed_scorer(tmp_path):
    source = (
        "def opaque_metric(model, row):\n"
        "    labels = model.labels\n"
        "    values = normalize(model.raw(row))\n"
        "    return dict(zip(labels, values))\n\n"
        "@app.post('/inspect')\n"
        "def inspect():\n"
        "    return jsonify(scores=opaque_metric(model, request.json['row']))\n"
    )
    assert len(_run(tmp_path, source, ModelExtractionPass)) == 1


def test_membership_signal_survives_renamed_metric_helper(tmp_path):
    source = (
        "def privacy_probe(model, row):\n"
        "    return model.opaque_metric(row)\n\n"
        "@app.get('/diagnostic')\n"
        "def diagnostic():\n"
        "    return jsonify(loss=privacy_probe(model, request.args['row']))\n"
    )
    assert len(_run(tmp_path, source, MembershipInferencePass)) == 1


def test_training_store_survives_renamed_model(tmp_path):
    source = (
        "class ArchiveEntry(db.Model):\n"
        "    \"\"\"Historical training examples used to fine-tune the assistant.\"\"\"\n\n"
        "def hidden_archive():\n"
        "    return [row.body for row in ArchiveEntry.query.all()]\n\n"
        "def answer(prompt):\n"
        "    return {'answer': generate(prompt) + '\\n'.join(hidden_archive())}\n\n"
        "@app.post('/chat')\n"
        "def chat():\n"
        "    return jsonify(**answer(request.json['message']))\n"
    )
    assert len(_run(tmp_path, source, TrainingDisclosurePass)) == 1

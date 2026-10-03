from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.training_approval import TrainingApprovalPass

_MODEL = """
class Feedback:
    \"\"\"User-submitted corrections waiting for moderator review.\"\"\"
    features = Column(Text)
    label = Column(String)
    status = Column(String, default="pending")
"""


def _scan(tmp_path: Path, worker: str):
    (tmp_path / "models.py").write_text(_MODEL, encoding="utf-8")
    (tmp_path / "worker.py").write_text(worker, encoding="utf-8")
    return TrainingApprovalPass().run(
        ScanContext(tmp_path, ScanConfig(tmp_path), ScanResult())
    ).findings


def test_unreviewed_feedback_entering_training_is_reported(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
def retrain(model):
    rows = Feedback.query.filter_by(model_id=model.id).all()
    scorer.apply_feedback(model, rows)
""",
    )
    assert len(findings) == 1
    assert findings[0].rule_id == "ML-UNREVIEWED-TRAINING-001"
    assert findings[0].cwe_ids == [829]
    assert findings[0].metadata["evidence_tier"] == "engine"


def test_approved_query_filter_suppresses_finding(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
def retrain(model):
    rows = Feedback.query.filter_by(model_id=model.id, status="approved").all()
    scorer.apply_feedback(model, rows)
""",
    )
    assert findings == []


def test_post_read_approval_filter_suppresses_finding(tmp_path: Path) -> None:
    findings = _scan(
        tmp_path,
        """
def retrain(model):
    pending = Feedback.query.filter_by(model_id=model.id).all()
    approved = [row for row in pending if row.status == "approved"]
    trainer.fit(model, approved)
""",
    )
    assert findings == []


def test_per_record_training_requires_approval_guard(tmp_path: Path) -> None:
    unsafe = _scan(
        tmp_path,
        """
def retrain(model):
    rows = Feedback.query.filter_by(model_id=model.id).all()
    for row in rows:
        trainer.partial_fit(model, row)
""",
    )
    assert len(unsafe) == 1

    safe_root = tmp_path / "safe"
    safe_root.mkdir()
    safe = _scan(
        safe_root,
        """
def retrain(model):
    rows = Feedback.query.filter_by(model_id=model.id).all()
    for row in rows:
        if row.status != "approved":
            continue
        trainer.partial_fit(model, row)
""",
    )
    assert safe == []


def test_operational_job_records_are_not_training_feedback(tmp_path: Path) -> None:
    (tmp_path / "models.py").write_text(
        """
class Job:
    payload = Column(Text)
    status = Column(String, default="pending")
""",
        encoding="utf-8",
    )
    (tmp_path / "worker.py").write_text(
        """
def train(model):
    rows = Job.query.filter_by(model_id=model.id).all()
    trainer.fit(model, rows)
""",
        encoding="utf-8",
    )
    findings = TrainingApprovalPass().run(
        ScanContext(tmp_path, ScanConfig(tmp_path), ScanResult())
    ).findings
    assert findings == []

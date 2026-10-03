"""Authz findings from different handlers must not be merged by adjacent-line
dedup (BACKLOG AZ-01). Runs the full pipeline, since the merge happens in
EnrichmentPass, not in the authz passes."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.passes.js_cross_file import TREE_SITTER_AVAILABLE
from rowan.pipeline import ScanPipeline

_MODELS = """from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


class Document(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer)
    body = db.Column(db.Text)
"""

_FLASK = """from flask import Flask, request, abort
from flask_login import current_user, login_required
from models import Document

app = Flask(__name__)


@app.route("/ok/<int:doc_id>")
@login_required
def get_ok(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc.body


@app.route("/a/<int:doc_id>")
@login_required
def get_a(doc_id):
    doc = Document.query.get(doc_id)
    return doc.body


@app.route("/b/<int:doc_id>")
@login_required
def get_b(doc_id):
    doc = Document.query.get(doc_id)
    return doc.body


@app.route("/c/<int:doc_id>")
@login_required
def get_c(doc_id):
    doc = Document.query.get(doc_id)
    return doc.body
"""

_EXPRESS = """const express = require("express");
const app = express();
const Doc = require("./models/doc");

app.get("/ok/:id", auth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  if (doc.ownerId !== req.user.id) return res.status(403).json({ error: "forbidden" });
  res.json(doc);
});

app.get("/a/:id", auth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  res.json(doc);
});

app.get("/b/:id", auth, async (req, res) => {
  const doc = await Doc.findById(req.params.id);
  res.json(doc);
});
"""


def _bola_lines(root: Path, name: str) -> list[int]:
    result = ScanPipeline(ScanConfig(target=root, enable_sca=False, enable_authz=True)).run()
    return sorted(
        f.start_line
        for f in result.findings
        if f.rule_id == "AUTHZ-BOLA-001" and Path(f.file_path).name == name
    )


def test_three_flask_handlers_keep_three_findings(tmp_path: Path):
    (tmp_path / "models.py").write_text(_MODELS, encoding="utf-8")
    (tmp_path / "app.py").write_text(_FLASK, encoding="utf-8")
    assert _bola_lines(tmp_path, "app.py") == [20, 27, 34]


@pytest.mark.skipif(not TREE_SITTER_AVAILABLE, reason="tree-sitter not installed")
def test_two_express_handlers_keep_two_findings(tmp_path: Path):
    (tmp_path / "routes.js").write_text(_EXPRESS, encoding="utf-8")
    assert _bola_lines(tmp_path, "routes.js") == [12, 17]

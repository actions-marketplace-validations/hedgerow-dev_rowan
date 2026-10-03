from flask import Flask, session, abort, jsonify
from models import Document

app = Flask(__name__)


@app.route("/a/<int:doc_id>")
def get_a(doc_id):
    doc = Document.query.get(doc_id)
    return jsonify(doc.body)


@app.route("/b/<int:doc_id>")
def get_b(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != session["user_id"]:
        abort(403)
    return jsonify(doc.body)

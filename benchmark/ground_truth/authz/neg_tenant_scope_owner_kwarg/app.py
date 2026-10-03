from flask import Flask, request, abort, jsonify
from flask_login import current_user, login_required, login_user
from models import Document, Tag, User

app = Flask(__name__)


@app.route("/guarded/<int:doc_id>")
@login_required
def get_guarded(doc_id):
    doc = Document.query.get(doc_id)
    if doc.owner_id != current_user.id:
        abort(403)
    return doc.body


@app.route("/mine")
@login_required
def mine():
    docs = Document.query.filter_by(owner=current_user).all()
    return jsonify([d.id for d in docs])


@app.route("/tags")
@login_required
def tags():
    return jsonify([t.name for t in Tag.query.all()])

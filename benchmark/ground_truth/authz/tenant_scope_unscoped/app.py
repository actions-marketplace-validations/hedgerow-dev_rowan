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


@app.route("/new", methods=["POST"])
@login_required
def new():
    doc = Document(owner_id=current_user.id, body=request.form["body"])
    return jsonify(doc.id)


@app.route("/all")
@login_required
def everything():
    docs = Document.query.all()
    return jsonify([d.id for d in docs])

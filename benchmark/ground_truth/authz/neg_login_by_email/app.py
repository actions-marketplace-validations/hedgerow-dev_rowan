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


@app.route("/login", methods=["POST"])
def login():
    user = User.query.filter_by(email=request.form["email"]).first()
    if not user or not user.check_password(request.form["password"]):
        return jsonify({"error": "bad creds"}), 401
    login_user(user)
    return jsonify({"ok": True})

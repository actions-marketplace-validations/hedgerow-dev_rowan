"""Webhook registration API.

The handler persists the subscriber-supplied callback URL and returns. It
never delivers anything itself, so there is no call edge from here to the
delivery worker.
"""

import secrets

from flask import Blueprint, jsonify, request

from notify.models import Webhook, db

bp = Blueprint("webhooks", __name__, url_prefix="/api/v1")


@bp.route("/webhooks", methods=["POST"])
def register_webhook():
    payload = request.get_json(force=True)
    if not payload.get("target_url"):
        return jsonify({"error": "target_url is required"}), 400

    hook = Webhook(
        owner_id=payload["owner_id"],
        target_url=payload["target_url"],
        secret=secrets.token_hex(16),
        active=True,
    )
    db.session.add(hook)
    db.session.commit()
    return jsonify({"id": hook.id, "secret": hook.secret}), 201


@bp.route("/webhooks/<int:hook_id>", methods=["DELETE"])
def deactivate_webhook(hook_id):
    hook = Webhook.query.get(hook_id)
    if hook is None:
        return jsonify({"error": "not found"}), 404
    hook.active = False
    db.session.commit()
    return "", 204

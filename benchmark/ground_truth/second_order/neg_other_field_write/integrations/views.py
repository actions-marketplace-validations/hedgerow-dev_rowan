"""Integration enablement.

The only user-controlled field written here is `display_label`. The URL the
dispatcher later reads comes from configuration.
"""

import secrets

from flask import Blueprint, jsonify, request

from integrations.models import PartnerHook, db
from integrations.settings import PARTNER_ENDPOINT

bp = Blueprint("integrations", __name__, url_prefix="/integrations")


@bp.route("/partner", methods=["POST"])
def enable_partner_integration():
    hook = PartnerHook(
        owner_id=int(request.form["owner_id"]),
        display_label=request.form["display_label"],
        target_url=PARTNER_ENDPOINT,
        secret=secrets.token_hex(16),
        active=True,
    )
    db.session.add(hook)
    db.session.commit()
    return jsonify({"id": hook.id}), 201

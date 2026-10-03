"""Host provisioning intake.

Requests land in a JSON state file that the reconciler picks up on its next
sweep. The API process cannot touch the network stack itself.
"""

import json
from pathlib import Path

from flask import Blueprint, jsonify, request

STATE_DIR = Path("/var/lib/provision")

bp = Blueprint("provision", __name__, url_prefix="/provision")


@bp.route("/hosts", methods=["POST"])
def enqueue_host():
    payload = request.get_json(force=True)
    pending_path = STATE_DIR / "pending.json"

    if pending_path.exists():
        with open(pending_path, encoding="utf-8") as handle:
            pending = json.load(handle)
    else:
        pending = []

    pending.append(
        {
            "hostname": payload["hostname"],
            "interface": payload["interface"],
            "requested_by": payload["requested_by"],
        }
    )
    with open(pending_path, "w", encoding="utf-8") as handle:
        json.dump(pending, handle)

    return jsonify({"queued": len(pending)}), 202

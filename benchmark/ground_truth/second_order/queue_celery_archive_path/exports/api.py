"""Archive request endpoint.

Dispatch is by task NAME over the broker, so there is no import of the worker
module here and no call edge for an interprocedural analysis to follow.
"""

from celery import Celery
from flask import Blueprint, jsonify, request

bp = Blueprint("exports", __name__, url_prefix="/exports")
celery_app = Celery("api", broker="redis://localhost:6379/0")


@bp.route("/archives", methods=["POST"])
def request_archive():
    payload = request.get_json(force=True)
    prefix = payload.get("prefix")
    if not prefix:
        return jsonify({"error": "prefix is required"}), 400

    async_result = celery_app.send_task(
        "exports.workers.build_archive",
        args=[prefix, payload["retention_days"]],
    )
    return jsonify({"task_id": async_result.id}), 202

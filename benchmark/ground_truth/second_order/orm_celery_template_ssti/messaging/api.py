"""Tenant-facing template editor.

Tenants author their own notification bodies. Rendering happens later, in the
Celery worker, when an event actually fires.
"""

from flask import Blueprint, jsonify, request

from messaging.models import NotificationTemplate, db

bp = Blueprint("templates", __name__, url_prefix="/templates")


@bp.route("", methods=["POST"])
def save_template():
    form = request.form
    template = NotificationTemplate(
        tenant_id=int(form["tenant_id"]),
        name=form["name"],
        subject=form["subject"],
        body=form["body"],
        enabled=True,
    )
    db.session.add(template)
    db.session.commit()
    return jsonify({"id": template.id}), 201

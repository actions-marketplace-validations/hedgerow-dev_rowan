"""User preference endpoints.

The mail signature is cached on write so the mail path never has to hit the
database. Writer and reader share only the Redis key.
"""

import redis
from flask import Blueprint, jsonify, request

from prefs.settings import SIGNATURE_TTL

bp = Blueprint("prefs", __name__, url_prefix="/prefs")
cache = redis.Redis.from_url("redis://localhost:6379/2")


@bp.route("/signature", methods=["PUT"])
def update_signature():
    user_id = request.form["user_id"]
    markup = request.form["signature_html"]

    cache.setex(f"prefs:signature:{user_id}", SIGNATURE_TTL, markup)
    return jsonify({"cached": True}), 200

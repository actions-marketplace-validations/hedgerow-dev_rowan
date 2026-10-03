"""Chat intake.

Every user turn is written into the conversation memory buffer. The planner
reads that buffer back on the next turn, in a different request.
"""

from flask import Blueprint, jsonify, request
from langchain.memory import ConversationBufferMemory

bp = Blueprint("intake", __name__, url_prefix="/assistant")
memory = ConversationBufferMemory(memory_key="history", return_messages=False)


@bp.route("/turns", methods=["POST"])
def record_turn():
    payload = request.get_json(force=True)
    message = payload["message"]

    memory.save_context({"input": message}, {"output": payload.get("reply", "")})
    return jsonify({"recorded": True}), 201

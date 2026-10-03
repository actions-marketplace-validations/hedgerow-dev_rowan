"""Saved-query library.

Analysts publish SQL snippets with a plain-language description. The
description is embedded so the assistant can find the snippet later; the SQL
itself rides along as metadata and in the indexed text.
"""

from flask import Blueprint, jsonify, request
from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

bp = Blueprint("library", __name__, url_prefix="/library")

INDEX_PATH = "/var/lib/analytics/faiss"
snippet_index = FAISS.load_local(
    INDEX_PATH, OpenAIEmbeddings(), allow_dangerous_deserialization=False
)


@bp.route("/snippets", methods=["POST"])
def publish_snippet():
    description = request.form["description"]
    sql = request.form["sql"]

    snippet_index.add_texts(
        [f"{description}\n{sql}"],
        metadatas=[{"author_id": request.form["author_id"], "sql": sql}],
    )
    snippet_index.save_local(INDEX_PATH)
    return jsonify({"indexed": True}), 201

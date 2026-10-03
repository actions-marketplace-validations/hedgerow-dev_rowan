"""Bookmark ingestion.

Users submit a page and the URL it came from. Both go into the shared
retrieval index; the URL is carried as chunk metadata.
"""

from flask import Blueprint, jsonify, request
from langchain_community.vectorstores import Qdrant
from langchain_openai import OpenAIEmbeddings

bp = Blueprint("citations", __name__, url_prefix="/citations")

vector_store = Qdrant.from_existing_collection(
    collection_name="bookmarks",
    embedding=OpenAIEmbeddings(),
    url="http://localhost:6333",
)


@bp.route("/bookmarks", methods=["POST"])
def add_bookmark():
    payload = request.get_json(force=True)
    excerpt = payload["excerpt"]

    vector_store.add_texts(
        [excerpt],
        metadatas=[{"origin_url": payload["origin_url"], "title": payload["title"]}],
    )
    return jsonify({"indexed": True}), 201

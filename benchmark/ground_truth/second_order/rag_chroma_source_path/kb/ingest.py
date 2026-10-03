"""Document ingestion endpoint.

Any authenticated tenant can upload a document into the shared knowledge
base. The uploader chooses the `source` label that is stored alongside the
chunk, which is what the answering service later resolves back to a file.
"""

import chromadb
from flask import Blueprint, jsonify, request
from langchain_chroma import Chroma
from langchain_core.documents import Document
from langchain_openai import OpenAIEmbeddings
from langchain_text_splitters import RecursiveCharacterTextSplitter

bp = Blueprint("ingest", __name__, url_prefix="/kb")

_client = chromadb.PersistentClient(path="/var/lib/kb/chroma")
collection = Chroma(
    client=_client,
    collection_name="handbook",
    embedding_function=OpenAIEmbeddings(),
)
splitter = RecursiveCharacterTextSplitter(chunk_size=800, chunk_overlap=80)


@bp.route("/documents", methods=["POST"])
def upload_document():
    upload = request.files["document"]
    text = upload.read().decode("utf-8", errors="replace")
    source = request.form.get("source", upload.filename)

    chunks = [
        Document(page_content=chunk, metadata={"source": source})
        for chunk in splitter.split_text(text)
    ]
    collection.add_documents(chunks)
    return jsonify({"chunks": len(chunks)}), 201

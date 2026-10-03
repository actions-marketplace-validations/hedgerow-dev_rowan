"""Retrieval-augmented answering.

Retrieval runs in the query path, ingestion runs in the upload path. Neither
calls the other; the Chroma collection is the whole connection.
"""

import chromadb
from langchain_chroma import Chroma
from langchain_openai import OpenAIEmbeddings

from kb.storage import load_original

_client = chromadb.PersistentClient(path="/var/lib/kb/chroma")
vector_store = Chroma(
    client=_client,
    collection_name="handbook",
    embedding_function=OpenAIEmbeddings(),
)


def answer_question(question, top_k=4):
    docs = vector_store.similarity_search(question, k=top_k)
    if not docs:
        return {"context": "", "citations": []}

    context = "\n\n".join(doc.page_content for doc in docs)
    citation = load_original(docs[0].metadata["source"])
    return {"context": context, "citation": citation}

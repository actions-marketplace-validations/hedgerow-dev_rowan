"""Natural-language query assistant.

Given a question, find the closest published snippet and preview it. The
publisher of that snippet is a different user in a different request; the
FAISS index is the only thing joining the two halves.
"""

from langchain_community.vectorstores import FAISS
from langchain_openai import OpenAIEmbeddings

from analytics.warehouse import run_subquery

INDEX_PATH = "/var/lib/analytics/faiss"
snippet_index = FAISS.load_local(
    INDEX_PATH, OpenAIEmbeddings(), allow_dangerous_deserialization=False
)


def preview_best_match(question):
    matches = snippet_index.similarity_search(question, k=1)
    if not matches:
        return {"rows": [], "snippet": None}

    rows = run_subquery(matches[0].metadata["sql"])
    return {"rows": rows, "snippet": matches[0].metadata["sql"]}

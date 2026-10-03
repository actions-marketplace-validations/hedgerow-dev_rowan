"""Citation freshness check.

Retrieves the bookmarks relevant to a topic and re-fetches each origin URL.
Same second-order shape as the other RAG cases, except the retrieved value
reaches the sink through a `for` loop variable rather than through the
variable the retrieval was assigned to.
"""

import logging

from langchain_community.vectorstores import Qdrant
from langchain_openai import OpenAIEmbeddings

from citations.fetcher import fetch_page

logger = logging.getLogger(__name__)

vector_store = Qdrant.from_existing_collection(
    collection_name="bookmarks",
    embedding=OpenAIEmbeddings(),
    url="http://localhost:6333",
)


def refresh_topic(topic, top_k=5):
    hits = vector_store.similarity_search(topic, k=top_k)

    refreshed = []
    for hit in hits:
        try:
            refreshed.append(fetch_page(hit.metadata["origin_url"]))
        except Exception:
            logger.warning("could not refresh %s", hit.metadata["title"])
    return refreshed

"""Semantic Kernel InMemoryVectorStore search with a request-controlled filter string (tnt-py-ai-skfilter-001, CWE-94)."""

from typing import Annotated

from fastapi import FastAPI
from pydantic import BaseModel
from semantic_kernel.connectors.in_memory import InMemoryVectorStore
from semantic_kernel.data.vector import VectorStoreField, vectorstoremodel

app = FastAPI()


@vectorstoremodel
class Note(BaseModel):
    id: Annotated[str, VectorStoreField("key")]
    text: Annotated[str, VectorStoreField("data", is_full_text_indexed=True)]
    embedding: Annotated[list[float] | None, VectorStoreField("vector", dimensions=1536)] = None


store = InMemoryVectorStore()
notes = store.get_collection(record_type=Note, collection_name="notes")


@app.get("/search")
async def search(query: str, filter_expr: str) -> list[str]:
    results = await notes.search(query, filter=filter_expr, top=5)
    return [item.record.text async for item in results.results]

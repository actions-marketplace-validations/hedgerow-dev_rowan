"""Report templating and note search on Semantic Kernel."""

from __future__ import annotations

from typing import Annotated

from pydantic import BaseModel
from semantic_kernel import Kernel
from semantic_kernel.connectors.ai.open_ai import OpenAIChatCompletion, OpenAITextEmbedding
from semantic_kernel.connectors.in_memory import InMemoryVectorStore
from semantic_kernel.data.vector import VectorStoreField, vectorstoremodel
from semantic_kernel.functions import KernelArguments
from semantic_kernel.prompt_template import KernelPromptTemplate, PromptTemplateConfig

kernel = Kernel()
kernel.add_service(OpenAIChatCompletion(service_id="chat"))
embedder = OpenAITextEmbedding(service_id="embed")


@vectorstoremodel
class Note(BaseModel):
    id: Annotated[str, VectorStoreField("key")]
    owner: Annotated[str, VectorStoreField("data", is_indexed=True)]
    text: Annotated[str, VectorStoreField("data", is_full_text_indexed=True)]
    embedding: Annotated[list[float] | None, VectorStoreField("vector", dimensions=1536)] = None


store = InMemoryVectorStore()
notes = store.get_collection(record_type=Note, collection_name="notes", embedding_generator=embedder)


async def render_report(template_text: str, ticket: dict) -> str:
    """Render a user-supplied report template against a ticket."""
    config = PromptTemplateConfig(template=template_text, name="report")
    template = KernelPromptTemplate(prompt_template_config=config)
    return await template.render(kernel, KernelArguments(**ticket))


async def search_notes(query: str, filter_expr: str) -> list[str]:
    """Search notes with a caller-supplied filter expression, e.g. owner == 'ops'."""
    await notes.ensure_collection_exists()
    results = await notes.search(query, filter=filter_expr, top=5)
    return [item.record.text async for item in results.results]

"""Semantic Kernel KernelPromptTemplate rendered from request text (tnt-py-ai-sktemplate-001, CWE-1336)."""

from fastapi import FastAPI
from semantic_kernel import Kernel
from semantic_kernel.functions import KernelArguments
from semantic_kernel.prompt_template import KernelPromptTemplate, PromptTemplateConfig

app = FastAPI()
kernel = Kernel()


@app.post("/render")
async def render(template_text: str, subject: str) -> dict:
    config = PromptTemplateConfig(template=template_text, name="report")
    template = KernelPromptTemplate(prompt_template_config=config)
    return {"text": await template.render(kernel, KernelArguments(subject=subject))}

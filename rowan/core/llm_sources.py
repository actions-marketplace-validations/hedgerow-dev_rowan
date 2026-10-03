"""Canonical "this value came from an LLM" recognizer (issue #185).

Two independent consumers need to answer the same question -- "is this text
an LLM completion or a model-chosen tool-call argument?" -- against different
inputs:

* `rowan/passes/enrichment.py`'s taint-origin classifier, matching a raw
  taint-flow source *snippet* (a string) to decide how much to trust it
  (DEF-44: the previous classifier scored model output as the SAFEST origin
  in the table, which is backwards for exactly this text).
* `rowan/core/authz_predicates.py`'s model-derived-authorization
  recognizer (`TNT-AUTHZ-001`/`AUTHZ-LLM-001`), matching an *AST expression*
  (via `ast.unparse`) to decide whether a value feeding an authorization
  decision or an ownership filter came from the model.

Before this module the two carried separately hand-written copies of the same
regex, which is the exact drift shape `rowan/rules_registry.py` exists to
prevent for the YAML rule corpus (DEF-10/14/15/19/26 in BACKLOG.md) -- the
same discipline applies here even though this is Python, not YAML.
"""

from __future__ import annotations

import re

#: Unambiguous LLM completion / tool-call shapes: OpenAI/Anthropic/LiteLLM
#: response fields and streaming deltas, plus a model-chosen tool-call's own
#: arguments payload.
LLM_COMPLETION_RE = re.compile(
    r"\.choices\[[^\]]*\]\.(?:message\.(?:content|text)|text)"
    r"|\.content\[[^\]]*\]\.text"
    r"|chat\.completions\.create"
    r"|ChatCompletion\.create"
    r"|litellm\.a?completion"
    r"|\.messages\.create"
    r"|\.delta\.content"
    r"|\.function\.arguments"
    # A model-chosen tool NAME is model output too (TE-06): OpenAI
    # `tool_call.function.name`, Anthropic `content_block.name`.
    r"|\.function\.name\b"
    r"|\b(?:tool_call|tool_use|content_block|block)\w*\.name\b"
    # Newer SDK entry points (AZ-20).
    r"|\.responses\.create"
    r"|\.messages\.stream"
    r"|\.generate_content\("
    r"|chat\.completions\.parse"
    # BACKLOG PY-01 agent SDK shapes, mirroring the `llm_output` fragment in
    # rules_registry.py (the YAML side is import-resolved; here the snippet
    # has already matched that rule, so the bare name is enough).
    r"|\bRunner\.run(?:_sync|_streamed)?\s*\("  # OpenAI Agents SDK
    r"|\bquery\s*\(\s*prompt\s*="  # Claude Agent SDK
    r"|\bdspy\.(?:Predict|ChainOfThought)\s*\("
    r"|\[[\"']llm[\"']\]\[[\"']replies[\"']\]"  # Haystack 2 Pipeline.run result
)

#: `.predict(...)`/`.generate(...)`/`.invoke(...)`/`.chat(...)` are ambiguous
#: on their own (a scikit-learn estimator has `.predict` too), so this is
#: gated on an LLM-named receiver. Mirrors the `$LLM` metavariable-regex
#: constraint `rules/llm_output_taint.yaml` and `rules/agent_taint.yaml`
#: already use for the identical judgment call, so the YAML corpus and this
#: Python code cannot drift on what counts as "LLM-shaped".
LLM_RECEIVER_CALL_RE = re.compile(
    r"(?i:\b\w*(llm|chatmodel|chat_model|agent|assistant|gpt|openai|anthropic"
    r"|deepseek|litellm|claude|gemini)\w*\s*\.\s*(?:predict|generate|invoke|chat)\b)"
    # BACKLOG PY-01: one alternative per name-gated block of the fragment.
    # Pydantic AI / LangChain `$CHAIN.run*`.
    r"|(?i:\b\w*(?:chain|agent|executor)\w*\s*\.\s*run(?:_sync|_stream)?\b)"
    # Google ADK runner instance (case-sensitive, as in the fragment).
    r"|\b\w*runner\w*\s*\.\s*run(?:_async)?\b"
    # Haystack 2 `pipeline.run(...)`.
    r"|(?i:\b\w*(?:pipeline|pipe)\w*\s*\.\s*run\b)"
    # Semantic Kernel `agent.get_response` / `kernel.invoke_prompt` / `kernel.invoke`.
    r"|(?i:\b\w*(?:kernel|agent)\w*\s*\.\s*(?:get_response|invoke_prompt|invoke)\b)"
    # DSPy module held in a variable, anchored to the whole callable name.
    r"|(?i:(?<![\w.])(?:self\.)?(?:\w*_)?(?:predict|predictor|cot|react)\s*\()"
)


def is_llm_derived_text(text: str) -> bool:
    """True if `text` (a taint-flow snippet, or `ast.unparse()` of an
    expression) is an unambiguous LLM completion or tool-call-argument shape."""
    return bool(LLM_COMPLETION_RE.search(text) or LLM_RECEIVER_CALL_RE.search(text))

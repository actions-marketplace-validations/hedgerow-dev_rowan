"""LangChain tool objects for the research agent."""

from __future__ import annotations

from langchain_core.tools import tool

from .queries import count_open, search_impl

search = tool(search_impl)
open_count = tool(count_open)

RESEARCH_TOOLS = [search, open_count]

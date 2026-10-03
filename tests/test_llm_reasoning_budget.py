"""Reasoning models exhaust the token budget on thinking and return empty
content, which used to be reported as a JSON parse failure.

DeepSeek v4 and the o-series bill reasoning against `max_tokens`, so an 8192
budget can be spent entirely on thinking, returning `finish_reason="length"`
with `content: ""`. Downstream that surfaced as "JSON parse failed", sending
whoever debugs it hunting for a malformed response that was never sent.
"""

from __future__ import annotations

import pytest

from rowan.agents.llm_backend import LLMBackend


class TestTokenBudgetConfig:
    def test_max_tokens_is_env_overridable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LLM_MAX_TOKENS", "32000")
        backend = LLMBackend(backend="deepseek", api_key="x")
        assert backend._max_tokens == 32000

    def test_max_tokens_falls_back_to_the_argument(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("LLM_MAX_TOKENS", raising=False)
        backend = LLMBackend(backend="deepseek", api_key="x", max_tokens=4096)
        assert backend._max_tokens == 4096

    def test_reasoning_effort_defaults_to_unset(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The field must be omitted from the payload entirely when unset, so
        endpoints that reject an unknown key are unaffected."""
        monkeypatch.delenv("LLM_REASONING_EFFORT", raising=False)
        backend = LLMBackend(backend="deepseek", api_key="x")
        assert backend._reasoning_effort == ""

    def test_reasoning_effort_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("LLM_REASONING_EFFORT", "low")
        backend = LLMBackend(backend="deepseek", api_key="x")
        assert backend._reasoning_effort == "low"


class TestEmptyResponseIsNotAParseFailure:
    def test_empty_string_reports_empty_not_parse_failure(self) -> None:
        result = LLMBackend._parse_json_response("")
        assert result["error"] == "empty LLM response"
        assert result["raw"] == ""

    def test_whitespace_only_is_also_empty(self) -> None:
        result = LLMBackend._parse_json_response("   \n  ")
        assert result["error"] == "empty LLM response", (
            "a whitespace-only body carries no more information than an empty one"
        )

    def test_genuinely_malformed_json_still_reports_a_parse_failure(self) -> None:
        """The distinction only helps if real parse failures keep their own
        message -- otherwise the fix trades one misleading error for another."""
        result = LLMBackend._parse_json_response("this is not json at all")
        assert result["error"] == "JSON parse failed"
        assert result["raw"] == "this is not json at all"

    def test_valid_json_is_unaffected(self) -> None:
        assert LLMBackend._parse_json_response('{"findings": []}') == {"findings": []}

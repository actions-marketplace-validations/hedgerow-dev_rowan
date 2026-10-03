"""Tests for the agentic hunt pipeline components."""

import json
from unittest.mock import MagicMock, patch

import pytest

from rowan.agents.llm_backend import LLMBackend
from rowan.agents.workflow import (
    HuntState,
    HuntWorkflow,
)
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, Severity


class TestLLMBackend:
    def test_unconfigured_returns_error(self):
        llm = LLMBackend(backend="deepseek", api_key="")
        assert not llm.is_configured
        resp = llm.generate("test")
        assert resp.text.startswith("LLM not configured")

    def test_auto_detect_backend(self):
        # Mock connectivity so a running local Ollama server doesn't interfere.
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
        ):
            llm = LLMBackend.from_env()
            assert not llm.is_configured  # No keys, no local server

    def test_auto_detect_ollama_prefers_installed_code_model(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=True),
            patch.object(
                LLMBackend,
                "_installed_ollama_models",
                return_value=["llama3.1:8b", "qwen2.5-coder:14b-16k"],
            ),
        ):
            llm = LLMBackend.from_env()

        assert llm._backend == "ollama"
        assert llm._model == "qwen2.5-coder:14b-16k"

    def test_auto_detect_preserves_explicit_model_override(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=True),
            patch.object(LLMBackend, "_installed_ollama_models") as installed,
        ):
            llm = LLMBackend.from_env(model="deepseek-r1:14b")

        installed.assert_not_called()
        assert llm._model == "deepseek-r1:14b"

    def test_credentials_are_read_live_not_captured_at_import(self):
        """Regression test: DEEPSEEK_API_KEY/OPENAI_API_KEY/OPENROUTER_API_KEY
        must be read from os.environ at construction time, not frozen as
        module-level constants when llm_backend.py is first imported. A
        credential set after import (e.g. by a test, or a .env loaded later
        in process startup) must still be picked up."""
        with patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-set-after-import"}, clear=True):
            llm = LLMBackend(backend="deepseek")
            assert llm.is_configured
            assert llm._api_key == "sk-set-after-import"

        with (
            patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-set-after-import"}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
        ):
            llm = LLMBackend.from_env()
            assert llm._backend == "deepseek"
            assert llm.is_configured

    def test_deepseek_config(self):
        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        assert llm.is_configured
        assert "deepseek" in repr(llm)

    def test_openrouter_config(self):
        llm = LLMBackend(backend="openrouter", api_key="sk-test", model="deepseek/deepseek-chat")
        assert llm.is_configured

    def test_alibaba_config(self):
        with patch.dict("os.environ", {}, clear=True):
            llm = LLMBackend(backend="alibaba", api_key="sk-test")
        assert llm.is_configured
        assert llm._model == "qwen3.8-max"
        assert (
            llm._base_url
            == "https://token-plan.ap-southeast-1.maas.aliyuncs.com/compatible-mode/v1"
        )

    def test_alibaba_env_overrides(self):
        env = {
            "ALIBABA_TOKEN_PLAN_API_KEY": "sk-test",
            "ALIBABA_MODEL": "qwen3.7-plus",
            "ALIBABA_BASE_URL": "https://token-plan.cn-beijing.maas.aliyuncs.com/compatible-mode/v1",
        }
        with patch.dict("os.environ", env, clear=True):
            llm = LLMBackend(backend="alibaba")
        assert llm.is_configured
        assert llm._model == "qwen3.7-plus"
        assert llm._base_url.endswith("cn-beijing.maas.aliyuncs.com/compatible-mode/v1")

    def test_llm_timeout_env_override(self):
        with patch.dict("os.environ", {"LLM_TIMEOUT": "600"}, clear=True):
            llm = LLMBackend(backend="deepseek", api_key="sk-test")
        assert llm._timeout == 600

    def test_from_env_selects_alibaba_when_only_token_plan_key_set(self):
        with (
            patch.dict("os.environ", {"ALIBABA_TOKEN_PLAN_API_KEY": "sk-test"}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
        ):
            llm = LLMBackend.from_env()
            assert llm._backend == "alibaba"
            assert llm.is_configured

    def test_invalid_backend(self):
        with pytest.raises(ValueError):
            LLMBackend(backend="unknown")

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_successful_call(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": "Hello, world"}}],
            "usage": {"total_tokens": 10},
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        resp = llm.generate("Hello")
        assert resp.text == "Hello, world"
        assert resp.usage["total_tokens"] == 10
        assert resp.model == "deepseek-chat"

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_debug_logs_prompt_and_response(self, mock_post, caplog):
        """-v (which sets the "rowan" logger tree to DEBUG) must
        actually surface the full prompt/response from __name__-based module
        loggers like this one."""
        import logging

        mock_resp = MagicMock()
        mock_resp.json.return_value = {"choices": [{"message": {"content": "the response"}}]}
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        with caplog.at_level(logging.DEBUG, logger="rowan.agents.llm_backend"):
            llm.generate("a distinctive prompt marker", system="a distinctive system marker")

        request_log = next(r for r in caplog.records if "LLM request" in r.message)
        response_log = next(r for r in caplog.records if "LLM response" in r.message)
        assert "a distinctive prompt marker" in request_log.message
        assert "a distinctive system marker" in request_log.message
        assert "the response" in response_log.message

    def test_verbose_flag_logger_tree_reaches_module_loggers(self):
        """Regression guard for the cli.py -v fix: setting DEBUG on
        "rowan" (the package name) must make a __name__-based module
        logger's effective level DEBUG."""
        import logging

        logging.getLogger("rowan").setLevel(logging.DEBUG)
        try:
            child = logging.getLogger("rowan.agents.llm_backend")
            assert child.isEnabledFor(logging.DEBUG)
        finally:
            logging.getLogger("rowan").setLevel(logging.NOTSET)

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_structured_output(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '{"key": "value"}'}}],
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        result = llm.generate_structured("Give me JSON")
        assert result == {"key": "value"}

    @patch("rowan.agents.llm_backend.httpx.post")
    def test_structured_markdown_wrapped(self, mock_post):
        mock_resp = MagicMock()
        mock_resp.json.return_value = {
            "choices": [{"message": {"content": '```json\n{"key": "value"}\n```'}}],
        }
        mock_resp.raise_for_status.return_value = None
        mock_post.return_value = mock_resp

        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        result = llm.generate_structured("Give me JSON")
        assert result == {"key": "value"}

    def test_repr(self):
        llm = LLMBackend(backend="deepseek", api_key="sk-test")
        assert "deepseek:deepseek-chat" in repr(llm)
        assert "configured" in repr(llm)


class TestParseJsonResponse:
    # BACKLOG HN-03: a non-object JSON value must not escape as a list/int/str.

    def test_bare_non_object_returns_error_dict(self):
        for text in ("[1, 2]", "[]", "42", '"str"', "```json\n[{\"a\": 1}]\n```"):
            result = LLMBackend._parse_json_response(text)
            assert isinstance(result, dict), text
            assert "error" in result, text

    def test_object_still_parses(self):
        assert LLMBackend._parse_json_response('{"hypotheses": []}') == {"hypotheses": []}


class TestHuntWorkflow:
    def test_state_defaults(self, test_project_dir):
        config = ScanConfig(target=test_project_dir, languages=["python"])
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(
            target_path=test_project_dir,
            config=config,
            llm=llm,
        )

        assert state.surface == []
        assert state.http_sinks == []
        assert state.hypotheses == []
        assert state.chains == []
        assert not state.vulnerable
        assert state.stage == "init"

    def test_workflow_runs_without_llm(self, test_project_dir):
        """Pipeline completes even without LLM configured."""
        config = ScanConfig(
            target=test_project_dir,
            languages=["python"],
            no_sca=True,
            legacy_neuroscan=True,
        )
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(
            target_path=test_project_dir,
            config=config,
            llm=llm,
        )

        workflow = HuntWorkflow(state)
        result = workflow.run()

        assert result.stage == "report"
        assert len(result.surface) > 0
        # Without LLM, should still have findings but no hypotheses
        assert result.report != ""

    def test_workflow_extracts_http_sinks(self, test_project_dir):
        config = ScanConfig(
            target=test_project_dir, languages=["python"], no_sca=True, legacy_neuroscan=True
        )
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(target_path=test_project_dir, config=config, llm=llm)
        workflow = HuntWorkflow(state)
        workflow._recon()

        # SSRF fixture has a vuln_ssrf.py with httpx/requests
        assert len(state.surface) > 0
        # HTTP sinks may or may not exist depending on regex matches

    def test_workflow_extracts_command_sinks(self, test_project_dir):
        config = ScanConfig(
            target=test_project_dir, languages=["python"], no_sca=True, legacy_neuroscan=True
        )
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(target_path=test_project_dir, config=config, llm=llm)
        workflow = HuntWorkflow(state)
        workflow._recon()

        # vuln_cmd.py has subprocess with shell=True
        assert any(s["file"].endswith("vuln_cmd.py") for s in state.command_sinks)

    def test_workflow_stages(self, test_project_dir):
        config = ScanConfig(
            target=test_project_dir, languages=["python"], no_sca=True, legacy_neuroscan=True
        )
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(target_path=test_project_dir, config=config, llm=llm)
        workflow = HuntWorkflow(state)

        # Verify all stages are registered
        assert set(workflow._nodes.keys()) == {
            "recon",
            "hypothesize",
            "verify",
            "deepdive",
            "discover",
            "exploit",
            "webexploit",
            "report",
        }

        # `discover` is registered but unreachable unless opted in (ADR-0004):
        # with enable_discovery off, deepdive still routes straight to exploit.
        assert workflow._after_deepdive() == "exploit"
        state.enable_discovery = True
        assert workflow._after_deepdive() == "discover"

    def test_report_stage_failure_does_not_loop(self, test_project_dir):
        """Regression test for DEF-37: if the report stage itself raises,
        run() must not redirect back to "report" forever -- it should fall
        back to the non-LLM text summary and stop."""
        config = ScanConfig(
            target=test_project_dir, languages=["python"], no_sca=True, legacy_neuroscan=True
        )
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(target_path=test_project_dir, config=config, llm=llm)
        workflow = HuntWorkflow(state)

        report_calls = []

        def _failing_report():
            report_calls.append(1)
            raise json.JSONDecodeError("boom", "doc", 0)

        workflow._nodes["recon"] = lambda: "report"
        workflow._nodes["report"] = _failing_report

        result = workflow.run()

        # The report node must have been entered exactly once, not looped --
        # this is the actual regression guard (pre-fix, this would run
        # forever: exception -> next_stage="report" -> re-enter "report" ->
        # exception -> ...).
        assert len(report_calls) == 1
        # run() must terminate and fall back to the non-LLM text summary
        # (which legitimately surfaces the collected state.errors, including
        # this one) rather than hanging.
        assert result.report != ""
        assert "Rowan Hunt Report" in result.report

    def test_text_summary(self, test_project_dir):
        config = ScanConfig(target=test_project_dir, languages=["python"])
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(target_path=test_project_dir, config=config, llm=llm)
        state.surface = [MagicMock()]
        state.hypotheses = [
            {
                "rule_id": "TEST-001",
                "file": "test.py",
                "line": 10,
                "exploitability": "confirmed",
                "attack_story": "Test attack story",
            }
        ]
        state.chains = [
            {
                "type": "RCE",
                "source": "test.py:10",
                "confidence": "confirmed",
                "evidence_status": "resolved",
                "attack_story": "Test chain",
            }
        ]

        workflow = HuntWorkflow(state)
        summary = workflow._text_summary()

        assert "Rowan Hunt Report" in summary
        assert "TOP HYPOTHESES" in summary
        assert "confirmed" in summary
        assert "Test attack story" in summary
        assert "CONFIRMED CHAINS" in summary

    def test_build_chain(self, test_project_dir):
        config = ScanConfig(target=test_project_dir, languages=["python"])
        llm = LLMBackend(backend="deepseek", api_key="")

        state = HuntState(target_path=test_project_dir, config=config, llm=llm)
        workflow = HuntWorkflow(state)

        hypothesis = {
            "rule_id": "TEST-RCE",
            "file": "src/vuln_pickle.py",
            "line": 4,
            "exploitability": "confirmed",
            "deep_dive": "src/vuln_pickle.py:4",
            "attack_story": "Pickle RCE via user input",
        }

        # A "confirmed" label alone is a lead: no scan finding backs it yet.
        chain = workflow._build_chain(hypothesis)
        assert chain is not None
        assert chain["type"] == "TEST-RCE"
        assert "vuln_pickle.py" in chain["source"]
        assert chain["confidence"] == "confirmed"
        assert chain["attack_story"] == "Pickle RCE via user input"
        assert chain["status"] == "lead"
        assert "No TEST-RCE scan finding" in chain["lead_reason"]

        state.surface = [Finding(
            rule_id="TEST-RCE", message="pickle", severity=Severity.HIGH,
            category=Category.DESERIALIZATION,
            file_path=str(test_project_dir / "src" / "vuln_pickle.py"), start_line=5,
        )]
        not_upheld = workflow._build_chain(hypothesis)
        assert not_upheld["status"] == "lead"
        assert "did not uphold" in not_upheld["lead_reason"]

        upheld = workflow._build_chain({**hypothesis, "verify_verdict": "upheld"})
        assert upheld["status"] == "confirmed"
        assert upheld["evidence_state"] == "statically_validated"

        state.config.no_verify = True
        assert workflow._build_chain(hypothesis)["status"] == "confirmed"

        state.config.no_verify = False
        state.surface[0].start_line = 40  # outside the cited window
        assert workflow._build_chain({**hypothesis, "verify_verdict": "upheld"})["status"] == "lead"

    def test_run_hunt_convenience(self, test_project_dir):
        llm = LLMBackend(backend="deepseek", api_key="")

        from rowan.agents.workflow import run_hunt

        result = run_hunt(
            target=test_project_dir,
            llm=llm,
            languages=["python"],
            no_sca=True,
        )

        assert result.stage == "report"
        assert len(result.surface) > 0
        assert result.report != ""


class TestWebExploit:
    def test_runner_init(self):
        from rowan.agents.web_exploit import WebExploitRunner

        runner = WebExploitRunner(timeout=5)
        assert runner._timeout == 5

    def test_probe_empty_sinks(self):
        from rowan.agents.web_exploit import WebExploitRunner

        runner = WebExploitRunner(timeout=1)
        results = runner.probe_all([])
        assert results == []

    def test_context_manager(self):
        from rowan.agents.web_exploit import WebExploitRunner

        with WebExploitRunner(timeout=1) as runner:
            results = runner.probe_all([])
            assert results == []

    def test_probe_classifies_ssti(self):
        from rowan.agents.web_exploit import _detect_ssti_vuln

        sink = {"file": "http://example.com", "rule": "ssti-001"}
        result = _detect_ssti_vuln(sink, timeout=3)
        assert result is None or isinstance(result, dict)

    def test_probe_classifies_sqli(self):
        from rowan.agents.web_exploit import _detect_sqli_vuln

        sink = {"file": "http://example.com", "rule": "sqli-001"}
        result = _detect_sqli_vuln(sink, timeout=3)
        assert result is None or isinstance(result, dict)


class TestExploitGating:
    """Live HTTP probes must be opt-in (issue #2) and require a real target
    (DEF-38): a source-file path in a sink's "file" field is never a live
    endpoint, so probing also requires --base-url plus a resolvable route."""

    def _state(self, tmp_path, enable_exploit, base_url=None):
        config = ScanConfig(target=tmp_path, languages=["python"], no_sca=True)
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(
            target_path=tmp_path,
            config=config,
            llm=llm,
            enable_exploit=enable_exploit,
            base_url=base_url,
        )
        state.http_sinks = [{"file": "app.py", "line": 5, "rule": "ssrf-001", "message": "ssrf"}]
        return state

    def test_webexploit_skipped_when_not_enabled(self, tmp_path):
        state = self._state(tmp_path, enable_exploit=False)
        workflow = HuntWorkflow(state)
        with patch("rowan.agents.web_exploit.WebExploitRunner") as runner:
            next_stage = workflow._webexploit()
        runner.assert_not_called()  # no live probing without opt-in
        assert next_stage == "report"
        assert state.chains == []
        assert state.vulnerable is False

    def test_webexploit_skipped_without_base_url(self, tmp_path):
        """--exploit alone has nothing live to probe (the original DEF-38 bug)."""
        state = self._state(tmp_path, enable_exploit=True)
        workflow = HuntWorkflow(state)
        with patch("rowan.agents.web_exploit.WebExploitRunner") as runner:
            next_stage = workflow._webexploit()
        runner.assert_not_called()
        assert next_stage == "report"

    def test_webexploit_skipped_without_resolvable_route(self, tmp_path):
        state = self._state(tmp_path, enable_exploit=True, base_url="http://localhost:5000")
        workflow = HuntWorkflow(state)
        with patch("rowan.agents.web_exploit.WebExploitRunner") as runner:
            next_stage = workflow._webexploit()
        runner.assert_not_called()  # no route extracted for this sink -> nothing to probe
        assert next_stage == "report"

    def test_webexploit_probes_route_built_from_base_url(self, tmp_path):
        state = self._state(tmp_path, enable_exploit=True, base_url="http://localhost:5000")
        state.http_sinks[0]["route"] = "/api/fetch"
        workflow = HuntWorkflow(state)
        with patch("rowan.agents.web_exploit.WebExploitRunner") as runner:
            runner.return_value.probe_all.return_value = []
            next_stage = workflow._webexploit()
        runner.assert_called_once()
        probed_sinks = runner.return_value.probe_all.call_args[0][0]
        assert probed_sinks[0]["url"] == "http://localhost:5000/api/fetch"
        assert next_stage == "report"

    def test_successful_live_probe_confirms_vulnerability(self, tmp_path):
        state = self._state(tmp_path, enable_exploit=True, base_url="http://localhost:5000")
        state.http_sinks[0]["route"] = "/api/fetch"
        workflow = HuntWorkflow(state)
        with patch("rowan.agents.web_exploit.WebExploitRunner") as runner:
            runner.return_value.probe_all.return_value = [
                {
                    "vulnerable": True,
                    "target": "http://localhost:5000/api/fetch",
                    "evidence": "probe response confirmed SSRF",
                }
            ]
            workflow._webexploit()

        assert state.vulnerable is True
        assert state.chains[0]["status"] == "confirmed"
        assert state.chains[0]["evidence_status"] == "resolved"
        assert state.chains[0]["evidence_state"] == "actively_confirmed"


class TestRoutePathExtraction:
    """DEF-38: a sink needs a real route path, extracted from its enclosing
    Flask-style decorator, before --base-url can build a live probe URL."""

    def _write_app(self, tmp_path, body):
        f = tmp_path / "app.py"
        f.write_text(body)
        return f

    def test_extracts_simple_route(self, tmp_path):
        f = self._write_app(
            tmp_path,
            (
                "from flask import Flask, request\n"
                "app = Flask(__name__)\n\n"
                '@app.route("/api/fetch")\n'
                "def fetch():\n"
                '    url = request.args.get("url")\n'
                "    return requests.get(url).text\n"
            ),
        )
        route = HuntWorkflow._extract_route_path(f, 6)
        assert route == "/api/fetch"

    def test_extracts_route_with_methods_kwarg(self, tmp_path):
        f = self._write_app(
            tmp_path,
            (
                '@app.route("/api/users", methods=["POST"])\n'
                "def create_user():\n"
                '    return db.execute(request.json["q"])\n'
            ),
        )
        route = HuntWorkflow._extract_route_path(f, 3)
        assert route == "/api/users"

    def test_replaces_converter_params_with_placeholder(self, tmp_path):
        f = self._write_app(
            tmp_path,
            (
                '@app.get("/api/users/<int:user_id>/files/<path:name>")\n'
                "def get_file(user_id, name):\n"
                "    return open(name).read()\n"
            ),
        )
        route = HuntWorkflow._extract_route_path(f, 3)
        assert route == "/api/users/1/files/1"

    def test_returns_none_when_no_decorator(self, tmp_path):
        f = self._write_app(tmp_path, ("def helper():\n    return open(name).read()\n"))
        assert HuntWorkflow._extract_route_path(f, 2) is None


class TestWebExploitEndToEnd:
    """Acceptance test for DEF-38: a probe must actually fire from a real
    hunt run when --exploit and --base-url are both given and a sink's
    enclosing function has a resolvable route."""

    def test_exploit_stage_sends_at_least_one_probe_given_base_url(self, tmp_path):
        # LFI/SQLi/SSTI probes build their request from the sink's own
        # target URL (base_url + route); SSRF sinks are not probed (HN-14),
        # so this uses a path-traversal sink to exercise the
        # base_url -> route -> request path end to end.
        (tmp_path / "app.py").write_text(
            "from flask import Flask, request\n"
            "app = Flask(__name__)\n\n"
            '@app.route("/api/files")\n'
            "def read_file():\n"
            '    name = request.args.get("name")\n'
            "    return open(name).read()\n"
        )
        config = ScanConfig(target=tmp_path, languages=["python"], no_sca=True)
        llm = LLMBackend(backend="deepseek", api_key="")
        state = HuntState(
            target_path=tmp_path,
            config=config,
            llm=llm,
            enable_exploit=True,
            base_url="http://localhost:5000",
        )
        state.lfi_sinks = [
            {
                "file": "app.py",
                "line": 6,
                "rule": "path-traversal-001",
                "message": "path traversal via open(request-controlled name)",
                "route": "/api/files",
            }
        ]

        workflow = HuntWorkflow(state)
        with patch("rowan.agents.web_exploit.httpx.get") as mock_get:
            mock_get.return_value = MagicMock(status_code=200, text="ok")
            next_stage = workflow._webexploit()

        assert next_stage == "report"
        assert mock_get.called  # at least one real probe request was sent
        probed_urls = [call.args[0] for call in mock_get.call_args_list]
        assert any(u.startswith("http://localhost:5000") for u in probed_urls)


class TestLLMEgressGate:
    """Declining LLM egress disables the backend so no code is sent (issue #3)."""

    def test_disable_clears_configuration(self):
        llm = LLMBackend(backend="deepseek", api_key="sk-test-not-real")
        assert llm.is_configured is True
        llm.disable()
        assert llm.is_configured is False


class TestDeepDiveScoping:
    """DeepDive must scan only the identified files, not the whole target (issue #28)."""

    def _state(self, target_path):
        config = ScanConfig(target=target_path, no_sca=True, legacy_neuroscan=True)
        llm = LLMBackend(backend="deepseek", api_key="")
        return HuntState(target_path=target_path, config=config, llm=llm)

    def test_resolves_relative_path_under_target(self, tmp_path):
        (tmp_path / "app.py").write_text("import pickle\npickle.loads(x)\n")
        state = self._state(tmp_path)
        workflow = HuntWorkflow(state)
        resolved = workflow._resolve_deepdive_files({"app.py"})
        assert resolved == {"app.py": tmp_path / "app.py"}

    def test_resolves_truncated_path_by_filename_search(self, tmp_path):
        nested = tmp_path / "src" / "pkg"
        nested.mkdir(parents=True)
        (nested / "vuln.py").write_text("import pickle\npickle.loads(x)\n")
        state = self._state(tmp_path)
        workflow = HuntWorkflow(state)
        # Hypothesis reports a suffix of the real path, not the exact relative path.
        resolved = workflow._resolve_deepdive_files({"pkg/vuln.py"})
        assert resolved == {"pkg/vuln.py": nested / "vuln.py"}

    def test_unresolvable_path_is_skipped(self, tmp_path):
        state = self._state(tmp_path)
        workflow = HuntWorkflow(state)
        resolved = workflow._resolve_deepdive_files({"does_not_exist.py"})
        assert resolved == {}

    def test_deepdive_scans_only_identified_file(self, tmp_path):
        # A second, unrelated file with a real finding must NOT appear in
        # deepdive_findings -- proves the re-scan is scoped, not whole-repo.
        (tmp_path / "target.py").write_text("import pickle\npickle.loads(x)\n")
        (tmp_path / "other.py").write_text("import pickle\npickle.loads(y)\n")

        state = self._state(tmp_path)
        state.surface = [
            Finding(
                rule_id="NS-DESER-001",
                message="target evidence",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path=str(tmp_path / "target.py"),
                start_line=2,
            ),
            Finding(
                rule_id="NS-DESER-001",
                message="other evidence",
                severity=Severity.HIGH,
                category=Category.DESERIALIZATION,
                file_path=str(tmp_path / "other.py"),
                start_line=2,
            ),
        ]
        state.hypotheses = [
            {
                "rule_id": "NS-DESER-001",
                "file": "target.py",
                "line": 2,
                "exploitability": "confirmed",
                "deep_dive": "target.py:2",
            }
        ]
        workflow = HuntWorkflow(state)
        next_stage = workflow._deepdive()

        assert next_stage == "exploit"
        findings = state.hypotheses[0]["deepdive_findings"]
        assert [finding["message"] for finding in findings] == ["target evidence"]
        assert state.hypotheses[0]["deepdive_evidence_source"] == "recon_full_context"

    def test_deepdive_noop_when_no_confirmed_hypotheses(self, tmp_path):
        state = self._state(tmp_path)
        state.hypotheses = [{"exploitability": "possible"}]
        workflow = HuntWorkflow(state)
        assert workflow._deepdive() == "exploit"

    def test_deepdive_noop_when_no_resolvable_targets(self, tmp_path):
        state = self._state(tmp_path)
        state.hypotheses = [{"exploitability": "confirmed", "deep_dive": "nonexistent.py:1"}]
        workflow = HuntWorkflow(state)
        assert workflow._deepdive() == "exploit"
        assert state.hypotheses[0].get("deepdive_findings") is None

    def test_deepdive_tolerates_explicit_null_deep_dive(self, tmp_path):
        """`.get("deep_dive", "")` only supplies the default when the key is
        ABSENT. A local model (observed: qwen2.5-coder against Langfail) can
        return `"deep_dive": null` explicitly for one hypothesis in a batch
        where others carry a real value -- `.get()` then returns None, and
        `.split(":")` on that used to crash the whole deepdive stage before
        `discover` (ADR-0004) ever ran. One resolvable hypothesis and one
        null-deep_dive hypothesis in the same batch is the exact shape that
        reproduced the crash."""
        (tmp_path / "target.py").write_text("import pickle\npickle.loads(x)\n")
        state = self._state(tmp_path)
        state.hypotheses = [
            {
                "rule_id": "NS-DESER-001",
                "file": "target.py",
                "line": 2,
                "exploitability": "confirmed",
                "deep_dive": "target.py:2",
            },
            {
                "rule_id": "NS-OTHER-001",
                "file": "target.py",
                "line": 1,
                "exploitability": "confirmed",
                "deep_dive": None,
            },
        ]
        workflow = HuntWorkflow(state)
        next_stage = workflow._deepdive()  # must not raise
        assert next_stage == "exploit"
        assert state.hypotheses[0].get("deepdive_findings") is not None
        assert state.hypotheses[1].get("deepdive_findings") == []

    def test_build_chain_tolerates_explicit_null_deep_dive(self, tmp_path):
        """Same root cause as the deepdive crash, at the second call site:
        `_build_chain` (called from `_exploit`, which is NOT skippable like
        deepdive) does `":" in dd` on the unguarded `.get()` result -- that
        raises TypeError on None, not just AttributeError, so this needed an
        independent fix even after the deepdive site was patched."""
        state = self._state(tmp_path)
        workflow = HuntWorkflow(state)
        hypothesis = {
            "rule_id": "NS-DESER-001",
            "file": "target.py",
            "line": 2,
            "exploitability": "confirmed",
            "attack_story": "test",
            "deep_dive": None,
        }
        chain = workflow._build_chain(hypothesis)  # must not raise
        assert chain is not None
        assert chain["source"] == "target.py:2"


class TestHuntBudget:
    @patch("rowan.agents.llm_backend.httpx.post")
    def test_hypothesize_stops_at_max_llm_calls(self, post, tmp_path):
        response = MagicMock(status_code=200, headers={})
        response.json.return_value = {
            "choices": [{"message": {"content": '{"hypotheses": []}'}}], "usage": {},
        }
        response.raise_for_status.return_value = None
        post.return_value = response
        llm = LLMBackend(backend="ollama")  # serial dispatch keeps the count exact
        llm.max_calls = 2
        state = HuntState(target_path=tmp_path, config=ScanConfig(target=tmp_path), llm=llm)
        state.surface = [
            Finding(rule_id=f"R-{i}", message="m", severity=Severity.HIGH,
                    category=Category.INJECTION, file_path="a.py", start_line=i + 1)
            for i in range(40)
        ]

        HuntWorkflow(state)._hypothesize()

        assert post.call_count == 2
        assert any("call budget of 2 exhausted" in e for e in state.errors)


def test_batch_size_for_kimi_via_openrouter():
    """HN-16: the Kimi batch limit follows the model, not a backend name."""
    from rowan.agents.workflow import _batch_size_for

    kimi = LLMBackend(backend="openrouter", model="moonshotai/kimi-k2", api_key="x")
    deepseek = LLMBackend(backend="deepseek", model="deepseek-chat", api_key="x")
    assert _batch_size_for(kimi, 10) == 8
    assert _batch_size_for(deepseek, 10) == 15


def test_workflow_has_no_edge_table(tmp_path):
    """HN-17: nodes return their next stage; there is no second routing table."""
    from rowan.agents.workflow import HuntState, HuntWorkflow

    state = HuntState(target_path=tmp_path, config=ScanConfig(target=tmp_path), llm=MagicMock())
    assert not hasattr(HuntWorkflow(state), "_edges")

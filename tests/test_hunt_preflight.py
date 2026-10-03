"""Tests for hunt's preflight tools -- estimate (free scope/cost preview) and
doctor (backend credential/connectivity checks)."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from rowan.agents.doctor import DoctorReport, run_doctor
from rowan.agents.estimate import HuntEstimate, estimate_hunt
from rowan.agents.llm_backend import LLMBackend, LLMResponse
from rowan.agents.workflow import HuntWorkflow
from rowan.core.findings import Category, Finding, Severity


class TestEstimateHunt:
    def test_estimate_runs_static_scan_only_no_llm_spend(self, test_project_dir):
        result = estimate_hunt(test_project_dir, languages=["python"], no_sca=True)

        assert isinstance(result, HuntEstimate)
        assert result.target == test_project_dir
        assert result.files_scanned > 0
        assert result.total_findings >= 0
        # priority_findings is a subset of total_findings
        assert result.priority_findings <= result.total_findings
        assert result.aiml_findings + result.generic_findings == result.priority_findings

    def test_estimate_batches_and_tokens_are_nonnegative(self, test_project_dir):
        result = estimate_hunt(test_project_dir, languages=["python"], no_sca=True)

        assert result.hypothesize_batches >= 0
        assert result.verify_candidates_estimate >= 0
        assert result.verify_batches_estimate >= 0
        assert result.input_tokens_estimate >= 0
        assert result.output_tokens_estimate >= 0

    def test_estimate_matches_workflow_priority_selection(self, test_project_dir):
        """The estimate must select the exact same findings hunt's real
        hypothesize stage would -- otherwise the projection is fiction."""
        from rowan.config import ScanConfig
        from rowan.pipeline import ScanPipeline

        config = ScanConfig(
            target=test_project_dir, languages=["python"], no_sca=True, no_taint=False
        )
        pipeline = ScanPipeline(config)
        scan_result = pipeline.run()

        expected_priority = HuntWorkflow._select_priority_findings(scan_result.findings)

        result = estimate_hunt(test_project_dir, languages=["python"], no_sca=True)
        assert result.priority_findings == len(expected_priority)

    def test_render_includes_key_fields(self):
        result = HuntEstimate(
            target=Path("/tmp/x"),
            files_scanned=10,
            total_findings=20,
            priority_findings=5,
            aiml_findings=2,
            generic_findings=3,
            hypothesize_batches=1,
            verify_candidates_estimate=3,
            verify_batches_estimate=1,
            input_tokens_estimate=1000,
            output_tokens_estimate=200,
        )
        rendered = result.render()
        assert "files scanned" in rendered
        assert "5" in rendered  # priority findings
        assert "not a bill" in rendered

    def test_render_shows_scan_errors_when_present(self):
        result = HuntEstimate(
            target=Path("/tmp/x"),
            files_scanned=1,
            total_findings=0,
            priority_findings=0,
            aiml_findings=0,
            generic_findings=0,
            hypothesize_batches=0,
            verify_candidates_estimate=0,
            verify_batches_estimate=0,
            input_tokens_estimate=0,
            output_tokens_estimate=0,
            scan_errors=["some pass failed"],
        )
        assert "scan errors" in result.render()


class TestSelectPriorityFindingsExcludesSca:
    """Depguard (SCA/dependency-CVE) findings carry no file/line context, so
    every one sent to hypothesize comes back a boilerplate false_positive --
    pure wasted LLM budget. They must never enter the priority set, even when
    high severity."""

    def _sca_finding(self, severity=Severity.HIGH):
        return Finding(
            rule_id="SCA-GHSA-xxxx",
            message="CVE in aiohttp: ",
            severity=severity,
            category=Category.SUPPLY_CHAIN,
            file_path="",
            start_line=0,
            engine="depguard",
        )

    def _code_finding(self):
        return Finding(
            rule_id="NS-DESER-001",
            message="Unsafe pickle loads detected",
            severity=Severity.HIGH,
            category=Category.DESERIALIZATION,
            file_path="src/app.py",
            start_line=15,
            engine="neuroscan",
        )

    def test_high_severity_depguard_finding_excluded(self):
        surface = [self._sca_finding(Severity.CRITICAL), self._code_finding()]
        priority = HuntWorkflow._select_priority_findings(surface)
        assert all(f.engine != "depguard" for f in priority)
        assert len(priority) == 1

    def test_medium_fallback_excludes_depguard(self):
        surface = [
            Finding(
                rule_id="SCA-GHSA-yyyy",
                message="CVE in pillow: ",
                severity=Severity.MEDIUM,
                category=Category.SUPPLY_CHAIN,
                file_path="",
                start_line=0,
                engine="depguard",
                confidence=0.8,
            ),
        ]
        priority = HuntWorkflow._select_priority_findings(surface)
        assert priority == []


class TestDoctor:
    def test_no_credentials_no_ollama(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
        ):
            report = run_doctor()

        assert isinstance(report, DoctorReport)
        assert all(not c.configured for c in report.checks if c.backend != "ollama")
        ollama_check = next(c for c in report.checks if c.backend == "ollama")
        assert not ollama_check.configured
        assert not report.ok

    def test_deepseek_configured_is_selected_and_ready(self):
        with (
            patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
        ):
            report = run_doctor()

        assert report.selected_backend == "deepseek"
        deepseek_check = next(c for c in report.checks if c.backend == "deepseek")
        assert deepseek_check.configured
        assert report.ok

    def test_ollama_reachable_marks_ready_without_live_flag(self):
        """Ollama's connectivity check IS the live check -- it's a local,
        free HTTP call, so it doesn't need the paid --live gate."""
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=True),
        ):
            report = run_doctor(live=False)

        assert report.selected_backend == "ollama"
        ollama_check = next(c for c in report.checks if c.backend == "ollama")
        assert ollama_check.configured
        assert ollama_check.live_ok is True
        assert report.ok

    def test_live_flag_probes_configured_cloud_backend(self):
        with (
            patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
            patch.object(
                LLMBackend,
                "generate",
                return_value=LLMResponse(text="pong", model="deepseek-chat"),
            ),
        ):
            report = run_doctor(live=True)

        deepseek_check = next(c for c in report.checks if c.backend == "deepseek")
        assert deepseek_check.live_ok is True
        assert report.ok

    def test_live_flag_catches_invalid_credential(self):
        with (
            patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-invalid"}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
            patch.object(
                LLMBackend,
                "generate",
                return_value=LLMResponse(text="LLM error: 401 Unauthorized", model="deepseek-chat"),
            ),
        ):
            report = run_doctor(live=True)

        deepseek_check = next(c for c in report.checks if c.backend == "deepseek")
        assert deepseek_check.configured  # key is present...
        assert deepseek_check.live_ok is False  # ...but doesn't work
        assert not report.ok  # selected backend fails live check -> not ready

    def test_render_marks_selected_backend(self):
        with (
            patch.dict("os.environ", {"DEEPSEEK_API_KEY": "sk-test"}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=False),
        ):
            report = run_doctor()

        rendered = report.render()
        assert "-> deepseek" in rendered
        assert "auto-detected pick: deepseek" in rendered
        assert "status: ready" in rendered

    def test_render_says_cli_uses_auto_detected_ollama(self):
        with (
            patch.dict("os.environ", {}, clear=True),
            patch.object(LLMBackend, "check_connectivity", return_value=True),
        ):
            report = run_doctor()

        rendered = report.render()
        assert report.selected_backend == "ollama"
        assert "hunt --backend auto" in rendered
        assert "uses this selection" in rendered


def test_no_project_config_ignores_repo_excludes(tmp_path: Path) -> None:
    from rowan.agents.workflow import resolve_hunt_scan_config

    (tmp_path / "app").mkdir()
    (tmp_path / ".rowan.yml").write_text("exclude:\n  - app/\n", encoding="utf-8")

    assert resolve_hunt_scan_config(tmp_path).extra_excludes == ["app/"]
    assert resolve_hunt_scan_config(tmp_path, project_config=False).extra_excludes == []

"""Policy parity guards for scan entry points that construct ScanConfig."""

from __future__ import annotations

import json
from pathlib import Path
from typing import ClassVar

import yaml

import rowan.agents.estimate as estimate_module
import rowan.agents.workflow as workflow_module
import rowan.mcp_server as mcp_server
from rowan.agents.llm_backend import LLMBackend
from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.scan_plan import build_scan_plan


class _RecordingPipeline:
    configs: ClassVar[list[ScanConfig]] = []

    def __init__(self, config: ScanConfig):
        self.configs.append(config)

    def run(self) -> ScanResult:
        return ScanResult()


def test_estimate_uses_default_engine_and_requested_sca_policy(tmp_path, monkeypatch):
    _RecordingPipeline.configs = []
    monkeypatch.setattr(estimate_module, "ScanPipeline", _RecordingPipeline)

    estimate_module.estimate_hunt(tmp_path, no_sca=True)

    plan = build_scan_plan(_RecordingPipeline.configs[-1])
    assert plan.effective_policy["converted_regex"] is True
    assert plan.effective_policy["opengrep_required"] is True
    assert plan.effective_policy["sca"] is False
    assert plan.effective_policy["report_view"] == "full"


def test_run_hunt_uses_same_default_engine_as_cli_hunt_and_estimate(
    tmp_path, monkeypatch
):
    captured: list[ScanConfig] = []

    class _RecordingWorkflow:
        def __init__(self, state):
            captured.append(state.config)
            self.state = state

        def run(self):
            return self.state

    monkeypatch.setattr(workflow_module, "HuntWorkflow", _RecordingWorkflow)
    llm = LLMBackend(backend="deepseek", api_key="")

    workflow_module.run_hunt(tmp_path, llm=llm, no_sca=True)

    plan = build_scan_plan(captured[-1])
    assert plan.effective_policy["converted_regex"] is True
    assert plan.effective_policy["opengrep_required"] is True
    assert plan.effective_policy["sca"] is False
    assert plan.effective_policy["report_view"] == "full"


def test_run_hunt_applies_project_policy_without_disabling_recon_taint(
    tmp_path, monkeypatch
):
    (tmp_path / ".rowan.yml").write_text(
        "policy: deep\nno_sca: true\nno_taint: true\n",
        encoding="utf-8",
    )
    captured: list[ScanConfig] = []

    class _RecordingWorkflow:
        def __init__(self, state):
            captured.append(state.config)
            self.state = state

        def run(self):
            return self.state

    monkeypatch.setattr(workflow_module, "HuntWorkflow", _RecordingWorkflow)
    workflow_module.run_hunt(
        tmp_path,
        llm=LLMBackend(backend="deepseek", api_key=""),
    )

    plan = build_scan_plan(captured[-1])
    assert plan.effective_policy["name"] == "deep"
    assert plan.effective_policy["sca"] is False
    assert plan.effective_policy["taint_dataflow"] is True


def test_mcp_evidence_keeps_intentional_actionable_offline_policy(
    tmp_path, monkeypatch
):
    _RecordingPipeline.configs = []
    monkeypatch.setattr(mcp_server, "ScanPipeline", _RecordingPipeline)

    # The policy is set in the scan worker's entry point; collect_evidence
    # runs it in a separate process, where this monkeypatch cannot reach.
    payload = json.loads(mcp_server._scan_to_json(str(tmp_path)))

    assert "error" not in payload
    plan = build_scan_plan(_RecordingPipeline.configs[-1])
    assert plan.effective_policy["converted_regex"] is True
    assert plan.effective_policy["sca"] is False
    assert plan.effective_policy["report_view"] == "actionable"
    assert payload["entrypoint_policy"] == {
        "name": "mcp_scan_evidence",
        "intentional_deltas": {
            "sca": "disabled_offline",
            "report_view": "actionable",
            "project_config": "not_loaded",
            "repo_ignore_files": "not_trusted",
        },
    }


def test_hunt_and_estimate_share_one_project_config_resolver(tmp_path):
    (tmp_path / ".rowan.yml").write_text(
        "policy: deep\nno_sca: true\nno_taint: true\nlanguages: [java]\n",
        encoding="utf-8",
    )
    hunt = workflow_module.resolve_hunt_scan_config(
        tmp_path, languages=None, no_sca=False, no_taint=False
    )
    estimate = workflow_module.resolve_hunt_scan_config(
        tmp_path, languages=None, no_sca=False, no_taint=False
    )

    assert build_scan_plan(hunt).as_dict() == build_scan_plan(estimate).as_dict()
    assert hunt.languages == estimate.languages == ["java"]
    assert hunt.policy == estimate.policy == "deep"
    assert hunt.no_sca is True
    assert hunt.no_taint is False


def test_github_action_names_project_config_trust_delta():
    action = (Path(__file__).parent.parent / "action.yml").read_text(
        encoding="utf-8"
    )
    assert 'cmd=(rowan scan "$TARGET" --ci)' in action
    assert 'cmd+=("${extra_args[@]}")' in action
    assert action.index('cmd+=("${extra_args[@]}")') < action.index(
        'cmd+=(--no-project-config -f sarif -o "$OUTPUT")'
    )


def test_github_action_pins_scanner_to_its_own_version_by_default():
    action = yaml.safe_load(
        (Path(__file__).parent.parent / "action.yml").read_text(encoding="utf-8")
    )
    assert action["inputs"]["ref"]["default"] == ""
    install = next(s for s in action["runs"]["steps"] if s.get("name") == "Install Rowan")
    assert 'pip install "$GITHUB_ACTION_PATH"' in install["run"]


def test_deepdive_reuses_recon_without_constructing_another_pipeline(
    tmp_path, monkeypatch
):
    source = tmp_path / "target.py"
    source.write_text("import pickle\npickle.loads(data)\n", encoding="utf-8")
    config = ScanConfig(
        target=tmp_path,
        no_sca=True,
        legacy_neuroscan=False,
    )
    state = workflow_module.HuntState(
        target_path=tmp_path,
        config=config,
        llm=LLMBackend(backend="deepseek", api_key=""),
    )
    state.hypotheses = [
        {
            "rule_id": "NS-DESER-001",
            "file": "target.py",
            "line": 2,
            "exploitability": "confirmed",
            "deep_dive": "target.py:2",
        }
    ]
    _RecordingPipeline.configs = []
    monkeypatch.setattr(workflow_module, "ScanPipeline", _RecordingPipeline)

    assert workflow_module.HuntWorkflow(state)._deepdive() == "exploit"
    assert _RecordingPipeline.configs == []
    assert state.hypotheses[0]["deepdive_evidence_source"] == "recon_full_context"

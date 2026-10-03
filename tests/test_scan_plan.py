"""Inspectable scan-plan construction and CLI dry-run behavior."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from rowan import cli
from rowan.config import ScanConfig
from rowan.scan_plan import build_scan_plan


def _names(items):
    return [item.name for item in items]


def test_default_plan_has_stable_execution_order(tmp_path):
    plan = build_scan_plan(ScanConfig(target=tmp_path))

    assert _names(plan.selected) == [
        "file_scan", "taint", "sca", "sibling_gate", "crossfile",
        "pii_egress", "training_disclosure", "model_extraction",
        "membership_inference", "dormant-code", "training-approval",
        "config-taint", "js_crossfile", "go_crossfile", "serialization-scope",
        "web-security", "agent-flow", "ast_enrichment", "mfv",
        "mcpconfig", "mcp-network-exposure", "mcp-sampling-approval",
        "mcp_tool_metadata", "mcp-stored-content", "instruction_smuggling",
        "enrichment",
    ]
    assert _names(plan.disabled) == ["authz", "js_authz", "multiagent"]
    assert plan.effective_policy["name"] == "default"
    assert plan.effective_policy["contract"] == {
        "deterministic": True,
        "source_analysis": "local",
        "llm": False,
        "source_egress": False,
        "advisory_network": True,
        "live_target": False,
    }
    assert plan.effective_policy["resource_budget"] == {
        "detector_workers": 4,
        "network_requests": 4,
        "network_source": "concurrency",
    }


def test_named_policies_have_explicit_capability_contracts(tmp_path):
    fast = build_scan_plan(ScanConfig(target=tmp_path, policy="fast"))
    deep = build_scan_plan(ScanConfig(target=tmp_path, policy="deep"))

    assert fast.effective_policy["taint_dataflow"] is False
    assert fast.effective_policy["cross_file"] is False
    assert {"sca", "crossfile", "authz", "multiagent"} <= set(_names(fast.disabled))

    assert deep.effective_policy["taint_dataflow"] is True
    assert deep.effective_policy["cross_file"] is True
    assert {"authz", "js_authz", "multiagent"} <= set(_names(deep.selected))
    assert deep.effective_policy["contract"]["advisory_network"] is True


def test_primitive_capability_overrides_win_over_policy(tmp_path):
    plan = build_scan_plan(ScanConfig(
        target=tmp_path,
        policy="fast",
        enable_sca=True,
        enable_taint=True,
        enable_cross_file=True,
        enable_authz=True,
        enable_multiagent=True,
    ))

    assert plan.effective_policy["sca"] is True
    assert plan.effective_policy["taint_dataflow"] is True
    assert plan.effective_policy["cross_file"] is True
    assert plan.effective_policy["authz"] is True
    assert plan.effective_policy["multiagent"] is True
    assert "sca" in _names(plan.selected)


def test_plan_explains_no_taint_engine_modes(tmp_path):
    converted = build_scan_plan(ScanConfig(target=tmp_path, no_taint=True))
    converted_taint = next(item for item in converted.selected if item.name == "taint")
    assert "converted regex rules only" in converted_taint.reason
    assert converted.effective_policy["taint_dataflow"] is False
    assert converted.effective_policy["opengrep_required"] is True

    legacy = build_scan_plan(ScanConfig(
        target=tmp_path,
        no_taint=True,
        legacy_neuroscan=True,
    ))
    legacy_taint = next(item for item in legacy.disabled if item.name == "taint")
    assert legacy_taint.reason == "no_taint with legacy_neuroscan"
    assert legacy.effective_policy["opengrep_required"] is False


def test_plan_reports_feature_groups_as_explicitly_disabled(tmp_path):
    plan = build_scan_plan(ScanConfig(
        target=tmp_path,
        no_sca=True,
        no_cross_file=True,
    ))
    disabled = {item.name: item.reason for item in plan.disabled}

    assert disabled["sca"] == "no_sca"
    assert disabled["crossfile"] == "no_cross_file"
    assert disabled["js_crossfile"] == "no_cross_file"
    assert disabled["authz"] == "authz not enabled"


@pytest.mark.parametrize("machine_readable", [False, True])
def test_explain_plan_resolves_project_config_without_running_pipeline(
    tmp_path, monkeypatch, machine_readable
):
    (tmp_path / ".rowan.yml").write_text(
        "no_sca: true\nno_cross_file: true\n",
        encoding="utf-8",
    )

    class UnexpectedPipeline:
        def __init__(self, config):
            pytest.fail("--explain-plan must not construct the scan pipeline")

    monkeypatch.setattr(cli, "ScanPipeline", UnexpectedPipeline)
    args = ["scan", str(tmp_path), "--explain-plan"]
    if machine_readable:
        args += ["--format", "json"]

    result = CliRunner().invoke(cli.main, args)

    assert result.exit_code == 0, result.output
    assert str(tmp_path) not in result.output
    if machine_readable:
        payload = json.loads(result.output)
        disabled = {item["name"] for item in payload["disabled_passes"]}
        assert {"sca", "crossfile", "js_crossfile"} <= disabled
        assert payload["effective_policy"]["sca"] is False
    else:
        assert "Rowan scan plan" in result.output
        assert "explicitly disabled" in result.output
        assert "no_cross_file" in result.output


def test_explain_plan_still_validates_effective_project_config(tmp_path, monkeypatch):
    (tmp_path / ".rowan.yml").write_text(
        "languages: [pythn]\n",
        encoding="utf-8",
    )

    class UnexpectedPipeline:
        def __init__(self, config):
            pytest.fail("invalid plan must not construct the scan pipeline")

    monkeypatch.setattr(cli, "ScanPipeline", UnexpectedPipeline)
    result = CliRunner().invoke(
        cli.main,
        ["scan", str(tmp_path), "--explain-plan"],
    )

    assert result.exit_code == 2
    assert "Unsupported language(s): pythn" in result.output


def test_explain_plan_order_matches_execution(tmp_path):
    """PL-12: the printed order is the order the pipeline runs passes in."""
    from rowan.pipeline import ScanPipeline

    (tmp_path / "app.py").write_text("x = 1\n", encoding="utf-8")
    config = ScanConfig(target=tmp_path, enable_sca=False)
    planned = _names(build_scan_plan(config).in_execution_order())
    ran = [o["name"] for o in ScanPipeline(config).run().metadata["pass_outcomes"]]
    assert [name for name in planned if name in ran] == ran

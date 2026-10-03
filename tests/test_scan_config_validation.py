"""Library-level validation of effective scan options."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import (
    MAX_LOCAL_CONCURRENCY,
    MAX_TAINT_TIMEOUT_SECONDS,
    ScanConfig,
)
from rowan.pipeline import ScanPipeline


@pytest.mark.parametrize("report_view", ["audit", "strict", "", None])
def test_scan_config_rejects_unknown_report_view(tmp_path, report_view) -> None:
    with pytest.raises(ValueError, match="Unsupported report_view"):
        ScanConfig(target=tmp_path, report_view=report_view)


@pytest.mark.parametrize("report_view", ["full", "actionable", "confirmed"])
def test_scan_config_accepts_all_supported_report_views(tmp_path, report_view) -> None:
    assert ScanConfig(target=tmp_path, report_view=report_view).report_view == report_view


@pytest.mark.parametrize(
    ("field_name", "value"),
    [("output_format", "xml"), ("profile", "generic"), ("profile", "batch")],
)
def test_scan_config_rejects_unknown_format_and_profile(tmp_path, field_name, value) -> None:
    with pytest.raises(ValueError, match=rf"Unsupported {field_name}"):
        ScanConfig(target=tmp_path, **{field_name: value})


@pytest.mark.parametrize("profile", ["server", "library", "cli", "desktop", "auto"])
def test_scan_config_accepts_supported_profiles(tmp_path, profile) -> None:
    assert ScanConfig(target=tmp_path, profile=profile).profile == profile


@pytest.mark.parametrize(
    "field_name", ["taint_timeout", "taint_workers", "taint_jobs", "network_concurrency"]
)
@pytest.mark.parametrize("value", [0, -1, 1.5, False])
def test_scan_config_requires_positive_integer_taint_controls(tmp_path, field_name, value) -> None:
    with pytest.raises(ValueError, match=rf"{field_name} must be a positive integer"):
        ScanConfig(target=tmp_path, **{field_name: value})


def test_scan_config_uses_automatic_worker_policy_when_omitted(tmp_path) -> None:
    assert ScanConfig(target=tmp_path).taint_workers is None
    assert ScanConfig(target=tmp_path, taint_workers=None).taint_workers is None


def test_optional_taint_controls_can_use_automatic_defaults(tmp_path) -> None:
    config = ScanConfig(target=tmp_path, taint_timeout=None, taint_workers=None, taint_jobs=None)

    assert config.taint_timeout is None
    assert config.taint_workers is None
    assert config.taint_jobs is None


@pytest.mark.parametrize("value", [0, -1, 1.5, False])
def test_scan_config_requires_positive_shared_concurrency(tmp_path, value) -> None:
    with pytest.raises(ValueError, match="concurrency must be a positive integer"):
        ScanConfig(target=tmp_path, concurrency=value)


@pytest.mark.parametrize(
    "field_name", ["taint_timeout", "taint_workers", "taint_jobs", "network_concurrency"]
)
def test_scan_config_accepts_positive_taint_controls(tmp_path, field_name) -> None:
    assert getattr(ScanConfig(target=tmp_path, **{field_name: 1}), field_name) == 1


@pytest.mark.parametrize(
    ("field_name", "maximum"),
    [
        ("taint_timeout", MAX_TAINT_TIMEOUT_SECONDS),
        ("taint_workers", MAX_LOCAL_CONCURRENCY),
        ("taint_jobs", MAX_LOCAL_CONCURRENCY),
        ("network_concurrency", MAX_LOCAL_CONCURRENCY),
        ("concurrency", MAX_LOCAL_CONCURRENCY),
    ],
)
def test_scan_config_enforces_resource_safety_ceilings(tmp_path, field_name, maximum) -> None:
    assert getattr(ScanConfig(target=tmp_path, **{field_name: maximum}), field_name) == maximum
    with pytest.raises(ValueError, match=rf"{field_name} must be <= {maximum}"):
        ScanConfig(target=tmp_path, **{field_name: maximum + 1})


@pytest.mark.parametrize(
    ("artifacts", "message"),
    [
        ({"vex_path": Path("vex.json")}, "--vex"),
        ({"sbom_path": Path("sbom.json")}, "--sbom"),
        (
            {"vex_path": Path("vex.json"), "sbom_path": Path("sbom.json")},
            "--vex and --sbom",
        ),
    ],
)
def test_scan_config_rejects_artifacts_when_sca_is_disabled(tmp_path, artifacts, message) -> None:
    with pytest.raises(ValueError, match=message):
        ScanConfig(target=tmp_path, no_sca=True, **artifacts)


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "message"),
    [
        ("report_view", "audit", "Unsupported report_view"),
        ("taint_timeout", 0, "taint_timeout must be a positive integer"),
        ("taint_workers", -1, "taint_workers must be a positive integer"),
        ("taint_jobs", False, "taint_jobs must be a positive integer"),
        ("languages", ["python", ""], "Unsupported language"),
    ],
)
def test_pipeline_revalidates_mutated_effective_config_before_work(
    tmp_path, field_name, invalid_value, message
) -> None:
    config = ScanConfig(target=tmp_path)
    setattr(config, field_name, invalid_value)

    with pytest.raises(ValueError, match=message):
        ScanPipeline(config)


def test_pipeline_revalidates_mutated_sca_artifact_conflict(tmp_path) -> None:
    config = ScanConfig(target=tmp_path, no_sca=True)
    config.vex_path = tmp_path / "vex.json"

    with pytest.raises(ValueError, match="--no-sca cannot be used with --vex"):
        ScanPipeline(config)


def test_scan_config_requires_existing_directory_target(tmp_path) -> None:
    with pytest.raises(ValueError, match="target does not exist"):
        ScanConfig(target=tmp_path / "missing")

    source = tmp_path / "app.py"
    source.write_text("pass\n", encoding="utf-8")
    with pytest.raises(ValueError, match="target must be a directory"):
        ScanConfig(target=source)


@pytest.mark.parametrize("field_name", ["rules_dir", "taint_rules_dir"])
def test_scan_config_requires_existing_rule_directories(tmp_path, field_name) -> None:
    with pytest.raises(ValueError, match=rf"{field_name} must be an existing directory"):
        ScanConfig(target=tmp_path, **{field_name: tmp_path / "missing"})


@pytest.mark.parametrize("field_name", ["neuroscan_rules", "thresholds_path", "baseline_path"])
def test_scan_config_requires_existing_input_files(tmp_path, field_name) -> None:
    with pytest.raises(ValueError, match=rf"{field_name} must be an existing file"):
        ScanConfig(target=tmp_path, **{field_name: tmp_path / "missing.yaml"})


@pytest.mark.parametrize("value", ["", "   ", 3])
def test_scan_config_rejects_invalid_opengrep_config_entries(tmp_path, value) -> None:
    with pytest.raises(ValueError, match="opengrep_configs entries"):
        ScanConfig(target=tmp_path, opengrep_configs=[value])


@pytest.mark.parametrize("value", ["missing.yaml", "./missing", "ftp://rules.test/x"])
def test_scan_config_rejects_unsafe_or_missing_opengrep_configs(tmp_path, value) -> None:
    with pytest.raises(ValueError, match="opengrep_configs"):
        ScanConfig(target=tmp_path, opengrep_configs=[value])


def test_scan_config_accepts_registry_url_and_existing_opengrep_configs(
    tmp_path,
) -> None:
    local = tmp_path / "custom.yaml"
    local.write_text("rules: []\n", encoding="utf-8")

    for value in ("auto", "p/python", "https://rules.test/custom.yaml", str(local)):
        assert ScanConfig(target=tmp_path, opengrep_configs=[value]).opengrep_configs == [value]


@pytest.mark.parametrize("second_field", ["write_baseline_path", "vex_path", "sbom_path"])
def test_scan_config_rejects_colliding_write_destinations(tmp_path, second_field) -> None:
    report = tmp_path / "report.json"
    with pytest.raises(ValueError, match="Output paths must be distinct"):
        ScanConfig(target=tmp_path, output=report, **{second_field: report})


@pytest.mark.parametrize("field_name", ["output", "write_baseline_path", "vex_path", "sbom_path"])
def test_scan_config_validates_write_destination_shape(tmp_path, field_name) -> None:
    with pytest.raises(ValueError, match=rf"{field_name} must be a file path"):
        ScanConfig(target=tmp_path, **{field_name: tmp_path})

    destination = tmp_path / "missing" / "report.json"
    with pytest.raises(ValueError, match=rf"{field_name} parent must be"):
        ScanConfig(target=tmp_path, **{field_name: destination})


@pytest.mark.parametrize("write_field", ["output", "write_baseline_path", "vex_path", "sbom_path"])
def test_scan_config_rejects_baseline_input_output_collision(tmp_path, write_field) -> None:
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="baseline_path must not also be"):
        ScanConfig(
            target=tmp_path,
            baseline_path=baseline,
            **{write_field: baseline},
        )

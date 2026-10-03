"""Deterministic orchestration gates for FLOW-12.

These tests intentionally assert operation counts and normalized contracts, not
wall-clock time.  They are small enough for blocking CI and leave real-project
timing/memory benchmarks to the opt-in profiles described by FLOW-12.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from rowan.config import ScanConfig
from rowan.pipeline import ScanPipeline
from rowan.scan_plan import build_scan_plan


def _config(target: Path, **overrides) -> ScanConfig:
    return ScanConfig(
        target=target,
        no_sca=True,
        no_taint=True,
        legacy_neuroscan=True,
        profile="server",
        **overrides,
    )


def _normalized_result(result, root: Path) -> dict[str, object]:
    """Keep stable scan contracts while excluding paths and elapsed time."""

    findings = sorted(
        (
            finding.rule_id,
            str(Path(finding.file_path).relative_to(root)),
            finding.start_line,
            finding.severity.value,
            finding.engine,
        )
        for finding in result.findings
    )
    pass_outcomes = [
        {
            key: value
            for key, value in outcome.items()
            if key != "duration_seconds"
        }
        for outcome in result.metadata["pass_outcomes"]
    ]
    return {
        "findings": findings,
        "degraded_passes": dict(result.degraded_passes),
        "pass_outcomes": pass_outcomes,
        "skipped_passes": result.metadata["skipped_passes"],
        "scope_summary": result.metadata["scope_summary"],
        "source_snapshot": result.metadata["source_snapshot"],
        "resolved_policy": result.metadata["resolved_policy"],
        "filter_counts": result.metadata["filter_counts"],
    }


def test_pipeline_stays_within_reviewed_recursive_walk_budget(
    tmp_path: Path, monkeypatch
) -> None:
    """A selected pass cannot silently add another full-tree traversal.

    FileScan owns the source/artifact inventory. Instruction-smuggling is the
    one reviewed full-tree discovery exception. Use upper bounds so deleting
    that exception is an allowed improvement while adding a walk fails this CI
    gate.
    """

    (tmp_path / "app.py").write_text("def clean():\n    return 1\n", encoding="utf-8")
    original_rglob = Path.rglob
    root_walks: Counter[str] = Counter()

    def counted_rglob(path: Path, pattern: str):
        if path == tmp_path:
            root_walks[pattern] += 1
        return original_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", counted_rglob)

    ScanPipeline(_config(tmp_path)).run()

    assert set(root_walks) <= {"*"}
    assert root_walks["*"] <= 2
    assert sum(root_walks.values()) <= 2


def test_shared_snapshot_parses_each_python_file_at_most_once(tmp_path: Path) -> None:
    for name in ("app.py", "worker.py"):
        (tmp_path / name).write_text(
            "def clean():\n    return 1\n",
            encoding="utf-8",
        )

    result = ScanPipeline(_config(tmp_path)).run()
    stats = result.metadata["source_snapshot"]

    assert stats["text_misses"] == 2
    assert stats["python_ast_misses"] == 2
    assert stats["python_ast_entries"] == 2
    assert stats["python_ast_hits"] > 0
    assert stats["read_failures"] == 0
    assert stats["parse_failures"] == 0


def test_repeated_scan_has_equivalent_normalized_findings_and_coverage(
    tmp_path: Path,
) -> None:
    (tmp_path / "app.py").write_text(
        "def run(user):\n    return eval(user)\n",
        encoding="utf-8",
    )

    first = ScanPipeline(_config(tmp_path)).run()
    second = ScanPipeline(_config(tmp_path)).run()

    normalized = _normalized_result(first, tmp_path)
    assert normalized["findings"] == [
        ("NS-INJECT-001", "app.py", 2, "medium", "neuroscan")
    ]
    assert _normalized_result(second, tmp_path) == normalized


def test_serial_and_staged_execution_have_equivalent_contracts(tmp_path: Path) -> None:
    """Concurrency changes scheduling, never scan coverage or finding order."""
    (tmp_path / "app.py").write_text(
        "def run(user):\n    return eval(user)\n",
        encoding="utf-8",
    )
    (tmp_path / "worker.py").write_text(
        "def helper(value):\n    return value\n",
        encoding="utf-8",
    )

    serial = ScanPipeline(_config(tmp_path, concurrency=1)).run()
    staged = ScanPipeline(_config(tmp_path, concurrency=4)).run()

    assert _normalized_result(staged, tmp_path) == _normalized_result(serial, tmp_path)
    assert {item["stage"] for item in staged.metadata["pass_outcomes"]} == {
        "discovery", "detection", "correlation", "enrichment"
    }


def test_plan_option_matrix_has_stable_normalized_contract(tmp_path: Path) -> None:
    cases = (
        (
            ScanConfig(target=tmp_path),
            {"selected": 26, "disabled": 3, "authz": False, "multiagent": False},
        ),
        (
            _config(tmp_path, no_cross_file=True),
            {"selected": 13, "disabled": 16, "authz": False, "multiagent": False},
        ),
        (
            ScanConfig(
                target=tmp_path,
                enable_authz=True,
                enable_multiagent=True,
                languages=["typescript", "python"],
            ),
            {"selected": 29, "disabled": 0, "authz": True, "multiagent": True},
        ),
    )

    for config, expected in cases:
        first = build_scan_plan(config).as_dict()
        second = build_scan_plan(config).as_dict()
        assert second == first
        assert len(first["selected_passes"]) == expected["selected"]
        assert len(first["disabled_passes"]) == expected["disabled"]
        assert first["effective_policy"]["authz"] is expected["authz"]
        assert first["effective_policy"]["multiagent"] is expected["multiagent"]

    assert build_scan_plan(cases[-1][0]).effective_policy["languages"] == [
        "python",
        "typescript",
    ]

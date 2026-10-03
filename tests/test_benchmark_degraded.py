"""A degraded scan must never be recorded as a clean_code measurement (#273).

`ScanPipeline` reports partial analysis in `degraded_passes`, but
`run_clean_code` used to record whatever finding count came back. Since a
degraded scan yields FEWER findings, the failure was indistinguishable from a
precision improvement and would ratchet the baseline down to a number the
scanner cannot reproduce.

Observed on unmodified `main`: an intermittent opengrep batch failure took
chainlit from its baselined 54 findings to 47, with nothing in the benchmark
output indicating the scan was incomplete.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_benchmark_module():
    script_path = Path(__file__).parent.parent / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark_degraded", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_degraded"] = module
    spec.loader.exec_module(module)
    return module


class _FakeFinding:
    def __init__(self, severity: str = "medium"):
        self.severity = type("S", (), {"value": severity})()


def _install_manifest(benchmark, tmp_path: Path, repo_name: str = "fakerepo") -> Path:
    """Point the module at a temporary corpus with one existing repo."""
    gt = tmp_path / "ground_truth" / "clean_code"
    gt.mkdir(parents=True)
    repo_dir = tmp_path / "repos" / repo_name
    repo_dir.mkdir(parents=True)
    (gt / "manifest.json").write_text(
        json.dumps({"repos": [{"name": repo_name, "local_path": f"repos/{repo_name}"}]}),
        encoding="utf-8",
    )
    benchmark.GROUND_TRUTH = tmp_path / "ground_truth"
    benchmark.PROJECT_ROOT = tmp_path
    return gt


def test_degraded_repo_is_not_recorded_and_fails_the_run(tmp_path: Path, monkeypatch) -> None:
    benchmark = _load_benchmark_module()
    _install_manifest(benchmark, tmp_path)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"clean_code": {"fakerepo": {"total": 54, "high_critical": 3}}}),
        encoding="utf-8",
    )
    benchmark.BASELINE_PATH = baseline_path

    # Every attempt degrades, returning a truncated finding list.
    monkeypatch.setattr(
        benchmark,
        "_scan_dir_checked",
        lambda target, **kw: ([_FakeFinding()], {"taint": "opengrep partial on 1/4 batches"}),
    )

    ok, current = benchmark.run_clean_code(update_baseline=False)

    assert ok is False, "a degraded scan must fail the run, not pass quietly"
    # The stale-but-real baseline is preserved rather than overwritten with 1.
    assert current["fakerepo"] == {"total": 54, "high_critical": 3}


def test_degraded_scan_is_retried_and_a_clean_retry_is_recorded(tmp_path: Path, monkeypatch) -> None:
    """Batch failures are intermittent, so one degraded attempt must not
    condemn the repo -- but the recorded number must come from a clean run."""
    benchmark = _load_benchmark_module()
    _install_manifest(benchmark, tmp_path)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"clean_code": {"fakerepo": {"total": 2, "high_critical": 0}}}),
        encoding="utf-8",
    )
    benchmark.BASELINE_PATH = baseline_path

    calls = {"n": 0}

    def flaky(target, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            return ([_FakeFinding()], {"taint": "opengrep partial on 1/4 batches"})
        return ([_FakeFinding(), _FakeFinding()], {})

    monkeypatch.setattr(benchmark, "_scan_dir_checked", flaky)

    ok, current = benchmark.run_clean_code(update_baseline=False)

    assert calls["n"] == 2, "a degraded scan must be retried"
    assert ok is True
    assert current["fakerepo"]["total"] == 2, "the clean retry's count is the one recorded"


def test_update_baseline_never_writes_a_degraded_count(tmp_path: Path, monkeypatch) -> None:
    benchmark = _load_benchmark_module()
    _install_manifest(benchmark, tmp_path)
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps({"clean_code": {"fakerepo": {"total": 54, "high_critical": 3}}}),
        encoding="utf-8",
    )
    benchmark.BASELINE_PATH = baseline_path

    monkeypatch.setattr(
        benchmark,
        "_scan_dir_checked",
        lambda target, **kw: ([_FakeFinding()], {"taint": "opengrep partial"}),
    )

    ok, current = benchmark.run_clean_code(update_baseline=True)

    assert ok is False
    # Ratcheting a degraded 1 over a real 54 is the exact corruption to prevent.
    assert current["fakerepo"]["total"] == 54


def test_clean_code_resume_reuses_matching_completed_repo(tmp_path: Path, monkeypatch) -> None:
    benchmark = _load_benchmark_module()
    _install_manifest(benchmark, tmp_path)
    benchmark.BASELINE_PATH = tmp_path / "missing-baseline.json"
    checkpoint = tmp_path / "checkpoint.json"
    monkeypatch.setattr(benchmark, "_scanner_fingerprint", lambda: "scanner-v1")
    monkeypatch.setattr(benchmark, "_git_revision", lambda path: "repo-v1")
    calls = {"n": 0}

    def scan(target, **kwargs):
        calls["n"] += 1
        assert kwargs["taint_jobs"] == 2
        return ([_FakeFinding("high")], {})

    monkeypatch.setattr(benchmark, "_scan_dir_retrying", scan)
    first_ok, first = benchmark.run_clean_code(
        False, resume=True, checkpoint_path=checkpoint, taint_jobs=2
    )
    second_ok, second = benchmark.run_clean_code(
        False, resume=True, checkpoint_path=checkpoint, taint_jobs=2
    )

    assert first_ok and second_ok
    assert first == second == {"fakerepo": {"total": 1, "high_critical": 1}}
    assert calls["n"] == 1


def test_clean_code_repo_selection_rejects_unknown_name(tmp_path: Path, monkeypatch) -> None:
    benchmark = _load_benchmark_module()
    _install_manifest(benchmark, tmp_path)
    benchmark.BASELINE_PATH = tmp_path / "missing-baseline.json"
    monkeypatch.setattr(benchmark, "_scanner_fingerprint", lambda: "scanner-v1")

    import pytest

    with pytest.raises(ValueError, match="unknown clean-code repo"):
        benchmark.run_clean_code(False, repo_names={"typo"}, checkpoint_path=tmp_path / "c.json")


def _run_main(benchmark, monkeypatch, *argv: str) -> int:
    monkeypatch.setattr(sys, "argv", ["benchmark.py", *argv])
    return benchmark.main()


def test_degraded_paired_corpus_fails_the_gate(monkeypatch, capsys) -> None:
    """A degraded scan is not analysed code; the gate must not read it as a pass."""
    benchmark = _load_benchmark_module()
    degraded = {"degraded": {"crossfile": "pass failed: boom"}}
    monkeypatch.setattr(benchmark, "run_cross_file_cases", lambda: degraded)
    monkeypatch.setattr(benchmark, "run_authz_cases", lambda: degraded)
    monkeypatch.setattr(benchmark, "run_py_agent_cases", lambda: degraded)

    for corpus in ("cross_file", "authz", "py_agent_cases"):
        assert _run_main(benchmark, monkeypatch, "--corpus", corpus) == 1, corpus
        assert "FAIL: scan degraded" in capsys.readouterr().out

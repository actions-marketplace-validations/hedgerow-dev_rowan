"""OS-05 precision gate: any unreviewed HIGH/CRITICAL on a pinned repo fails."""

import subprocess
from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_precision_gate.py"
SPEC = spec_from_file_location("check_precision_gate", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
check = MODULE.check


def _repo(tmp_path) -> tuple[Path, str]:
    repo = tmp_path / "repo"
    (repo / "api").mkdir(parents=True)
    (repo / "api" / "login.py").write_text("x = 1\n", encoding="utf-8")
    git = ["git", "-C", str(repo), "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run([*git, "init", "-q"], check=True)
    subprocess.run([*git, "add", "."], check=True)
    subprocess.run([*git, "commit", "-qm", "init"], check=True)
    revision = subprocess.run(
        [*git, "rev-parse", "HEAD"], check=True, capture_output=True, text=True
    ).stdout.strip()
    return repo, revision


def _report(repo: Path, severity: str = "medium", **overrides) -> dict:
    report = {
        "report_view": "full",
        "summary": {"degraded": False},
        "coverage_summary": {"status": "complete"},
        "findings": [
            {
                "rule_id": "TNT-HEADER-001",
                "severity": severity,
                "file": str(repo / "api" / "login.py"),
                "line": 216,
            }
        ],
    }
    report.update(overrides)
    return report


def test_clean_report_at_pinned_revision_passes(tmp_path):
    repo, revision = _repo(tmp_path)
    entry = {"revision": revision[:7], "adjudicated_high": []}
    assert check(_report(repo), repo, entry) == []


def test_unreviewed_high_fails(tmp_path):
    repo, revision = _repo(tmp_path)
    entry = {"revision": revision[:7], "adjudicated_high": []}
    problems = check(_report(repo, "high"), repo, entry)
    assert problems == ["unreviewed high: TNT-HEADER-001 api/login.py:216"]


def test_adjudicated_high_passes(tmp_path):
    repo, revision = _repo(tmp_path)
    reviewed = {"rule_id": "TNT-HEADER-001", "path": "api/login.py", "line": 216}
    entry = {"revision": revision[:7], "adjudicated_high": [reviewed]}
    assert check(_report(repo, "critical"), repo, entry) == []


def test_wrong_revision_and_incomplete_report_fail(tmp_path):
    repo = _repo(tmp_path)[0]
    entry = {"revision": "0000000", "adjudicated_high": []}
    report = _report(repo, report_view="actionable", coverage_summary={"status": "incomplete"})
    problems = check(report, repo, entry)
    assert len(problems) == 3
    assert problems[0].startswith("checkout is at ")

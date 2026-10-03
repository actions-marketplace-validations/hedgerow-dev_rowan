"""Every supported entrypoint must behave identically.

Regression guard for the silent-failure bug where `python -m rowan.cli`
exited 0 with no banner, no findings and no report file because cli.py had no
`if __name__ == "__main__"` block. For a security scanner a silent clean exit
is worse than a crash: a CI job invoking the wrong form would report success on
vulnerable code.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from rowan import __version__
from rowan.taint.opengrep_adapter import OpengrepAdapter

REPO_ROOT = Path(__file__).resolve().parent.parent

# Both module forms of the CLI. The console script (rowan) resolves to the
# same callable via [project.scripts], so it is covered by proxy.
MODULE_FORMS = [
    ["-m", "rowan"],
    ["-m", "rowan.cli"],
]


def _run(form: list[str], *args: str) -> subprocess.CompletedProcess:
    """Invoke one entrypoint form in a subprocess.

    PYTHONPATH pins the child to this checkout. Without it an editable install
    pointing somewhere else would silently be the thing under test.
    """
    return subprocess.run(
        [sys.executable, *form, *args],
        cwd=REPO_ROOT,
        env={"PYTHONPATH": str(REPO_ROOT), "PATH": "/usr/bin:/bin", "HOME": str(Path.home())},
        capture_output=True,
        text=True,
        timeout=900,
    )


@pytest.mark.parametrize("form", MODULE_FORMS, ids=lambda f: " ".join(f))
def test_module_form_is_not_silent(form):
    """The bug: rc 0 with completely empty stdout."""
    result = _run(form, "--version")

    assert result.returncode == 0, result.stderr
    assert result.stdout.strip(), (
        f"`python {' '.join(form)} --version` produced no output at all. "
        "This is the silent-entrypoint failure mode."
    )


def test_module_forms_report_the_same_version():
    # Click prefixes its own program name, which differs per form by design, so
    # compare the version token rather than the whole line.
    versions = {
        " ".join(form): _run(form, "--version").stdout.strip().rsplit(" ", 1)[-1]
        for form in MODULE_FORMS
    }
    assert len(set(versions.values())) == 1, versions
    assert next(iter(versions.values())) == __version__


@pytest.mark.parametrize("form", MODULE_FORMS, ids=lambda f: " ".join(f))
def test_module_form_exposes_the_scan_command(form):
    result = _run(form, "--help")

    assert result.returncode == 0, result.stderr
    assert "scan" in result.stdout


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; comparing real scans needs a live engine.",
)
def test_module_forms_produce_equivalent_scan_reports(tmp_path):
    """Same target, same findings, and a report file actually gets written."""
    target = tmp_path / "target"
    target.mkdir()
    (target / "broker.py").write_text(
        "import pickle, zmq\n"
        'ctx = zmq.Context(); sock = ctx.socket(zmq.PULL); sock.bind("tcp://0.0.0.0:30000")\n'
        "while True:\n"
        "    frames = sock.recv_multipart()\n"
        "    req = pickle.loads(frames[-1])\n"
    )

    reports = {}
    for form in MODULE_FORMS:
        # Report goes outside the scanned tree so it cannot become scan input.
        out = tmp_path / f"report_{'_'.join(form).replace('-', '')}.json"
        result = _run(
            form, "scan", str(target), "--no-sca", "--format", "json", "-o", str(out)
        )

        assert result.returncode == 0, result.stderr
        assert out.exists(), (
            f"`python {' '.join(form)} scan` exited 0 but wrote no report to {out}."
        )
        reports[" ".join(form)] = json.loads(out.read_text())

    def fingerprint(report):
        return sorted(
            (f["rule_id"], Path(f["file"]).name, f["line"], f["severity"])
            for f in report["findings"]
        )

    fingerprints = {name: fingerprint(r) for name, r in reports.items()}
    first = next(iter(fingerprints.values()))

    # The fixture is a real vulnerability; an empty result means the scan did
    # not run, which is exactly the failure this module guards against.
    assert any(rule.startswith("TNT-DESER") for rule, _, _, _ in first), first
    assert len(set(map(tuple, fingerprints.values()))) == 1, fingerprints

    # duration_seconds is wall-clock noise; everything else must match.
    summaries = {}
    for name, report in reports.items():
        summary = dict(report["summary"])
        summary.pop("duration_seconds", None)
        summaries[name] = summary
    assert len({json.dumps(s, sort_keys=True) for s in summaries.values()}) == 1, summaries


@pytest.mark.parametrize("form", MODULE_FORMS, ids=lambda f: " ".join(f))
def test_module_form_emits_json_to_stdout_without_output_file(tmp_path, form):
    target = tmp_path / "target"
    target.mkdir()

    result = _run(
        form,
        "scan",
        str(target),
        "--format",
        "json",
        "--no-sca",
        "--no-taint",
        "--no-cross-file",
        "--legacy-neuroscan",
    )

    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert "summary" in report
    assert "findings" in report

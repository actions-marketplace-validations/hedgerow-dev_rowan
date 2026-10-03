"""Tracked, reproducible regressions for confirmed rowan defects.

Each test reproduces a real defect found by empirical comparison against
external tools (Protect AI ``modelscan`` for model-file scanning, Semgrep
community rules for SAST severity calibration). They are marked
``xfail(strict=True)`` so that:

  * while the defect exists, the suite stays green (expected failure);
  * the moment someone fixes the defect, the test XPASSes and strict mode
    turns that into a hard failure, forcing the author to delete the marker
    and lock the fix in as a normal passing test.

Do NOT relax these into ``assert ... or skip``. They are the acceptance
criteria for the linked backlog items (see BACKLOG.md "Confirmed defects").
"""

from __future__ import annotations

import io
import pickle
import tempfile
import zipfile
from collections import OrderedDict
from pathlib import Path

import pytest
from hayward import ModelFileScanner

from rowan.config import ScanConfig
from rowan.core.findings import Severity
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter


class _ReduceExploit:
    """Pickle that runs a shell command on load via __reduce__."""

    def __reduce__(self):
        import os

        return (os.system, ("echo pwned",))


# ---------------------------------------------------------------------------
# DEF-1 (FIXED, now a regression guard): payloads inside PyTorch zip archives
#
# Real torch.save() output is a ZIP container (default since PyTorch 1.6, 2020).
# scan_file now routes zip-backed .pt/.pth to _scan_pytorch_zip, which extracts
# and scans each inner pickle member (archive/data.pkl). If this test ever fails
# again, the zip-unwrapping path has regressed to flat-pickle scanning.
# ---------------------------------------------------------------------------
def test_mfv_detects_malicious_pickle_inside_pytorch_zip(tmp_path):
    """A malicious pickle stored inside a .pt zip archive must be flagged."""
    buf = io.BytesIO()
    pickle.dump(_ReduceExploit(), buf)

    pt_path = tmp_path / "model.pt"
    with zipfile.ZipFile(pt_path, "w") as zf:
        zf.writestr("archive/data.pkl", buf.getvalue())

    findings = ModelFileScanner().scan_file(pt_path)

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical, (
        "Expected a CRITICAL finding for the malicious pickle inside the "
        f".pt zip archive, got: {[(f.rule_id, f.severity) for f in findings]}"
    )


# ---------------------------------------------------------------------------
# DEF-2 (FIXED, now a regression guard): Severity miscalibration
#
# pickle.loads() on attacker-controlled request data is a critical
# deserialization RCE. The production taint engine must connect request data
# to the sink and retain HIGH severity. With taint disabled, a regex match
# stays MEDIUM: nearby request code must not impersonate a verified flow.
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("taint_enabled", [False, True])
def test_pickle_rce_severity_requires_dataflow(taint_enabled):
    """Actual taint earns HIGH; the regex-only fallback remains unconfirmed."""
    if taint_enabled and not OpengrepAdapter().is_installed():
        pytest.skip("Opengrep required to establish the source-to-sink flow")
    with tempfile.TemporaryDirectory(prefix="rowan_defect_") as d:
        src = Path(d) / "src"
        src.mkdir()
        (src / "vuln_deser.py").write_text(
            "import pickle\n"
            "from flask import request\n"
            "\n"
            "@app.route('/load')\n"
            "def load():\n"
            "    data = request.data\n"
            "    return pickle.loads(data)\n",
            encoding="utf-8",
        )

        config = ScanConfig(
            target=Path(d),
            no_taint=not taint_enabled,
            no_sca=True,
            languages=["python"],
            legacy_neuroscan=True,
        )
        result = ScanPipeline(config).run()

        severe = [
            f
            for f in result.findings
            if f.severity in (Severity.HIGH, Severity.CRITICAL)
        ]
        assert result.findings
        if taint_enabled:
            assert severe, [(f.rule_id, f.severity.value) for f in result.findings]
            assert any(f.taint_flow is not None for f in severe)
        else:
            assert not severe
            assert all(f.metadata["evidence_tier"] == "pattern-only" for f in result.findings)


# ---------------------------------------------------------------------------
# DEF-3 (FIXED, now a regression guard): MFV gave a benign model the same
# verdict as real malware
#
# The pickle scanner used to flag the mere *presence* of REDUCE/STACK_GLOBAL/
# GLOBAL/BUILD opcodes as CRITICAL. Those opcodes appear in essentially every
# real pickle-serialized object -- an OrderedDict, a tensor rebuild -- so a
# completely benign checkpoint and an os.system() backdoor got the identical
# CRITICAL verdict. _scan_pickle now resolves each GLOBAL/STACK_GLOBAL to its
# `module.name` callable (_resolve_pickle_globals) and classifies it against
# an allow/deny list (_classify_pickle_global); only a denied callable
# (os.system, eval, subprocess, ...) produces MFV-PICKLE-001/CRITICAL. If
# this test ever fails again, that classification has regressed back to
# presence-only opcode counting -- which is exactly what made the scanner
# unable to issue a trustworthy "clean" verdict at all.
# ---------------------------------------------------------------------------
def test_mfv_does_not_flag_benign_pickle_as_critical(tmp_path):
    """An ordinary OrderedDict pickle (a real torch.save state_dict shape)
    must not be flagged, while a real __reduce__-based backdoor still is."""
    benign = OrderedDict((f"layer{i}.weight", [[0.1, 0.2, 0.3]] * 4) for i in range(5))
    benign_path = tmp_path / "benign_state.pkl"
    benign_path.write_bytes(pickle.dumps(benign))

    evil_path = tmp_path / "evil.pkl"
    evil_path.write_bytes(pickle.dumps(_ReduceExploit()))

    scanner = ModelFileScanner()
    benign_findings = scanner.scan_file(benign_path)
    evil_findings = scanner.scan_file(evil_path)

    assert not any(f.severity == Severity.CRITICAL for f in benign_findings), (
        "Expected a benign OrderedDict pickle to produce no CRITICAL findings, "
        f"got: {[(f.rule_id, f.severity.value) for f in benign_findings]}"
    )
    assert any(f.severity == Severity.CRITICAL for f in evil_findings), (
        "Expected the os.system() __reduce__ backdoor to still be CRITICAL, "
        f"got: {[(f.rule_id, f.severity.value) for f in evil_findings]}"
    )


# ---------------------------------------------------------------------------
# DEF-31 (FIXED, now a regression guard): pickle INST opcode bypass
#
# _resolve_pickle_globals only handled the GLOBAL/STACK_GLOBAL opcodes.
# Protocol 0's INST opcode resolves a callable through the identical
# find_class(module, name) path GLOBAL uses, then calls it directly with
# whatever args were pushed since the preceding MARK -- and was completely
# invisible to the walker, so a hand-crafted protocol-0 pickle invoking
# os.system() via INST produced zero findings (a full scanner bypass). An
# INST branch now reads the same "module qualname" argument shape GLOBAL
# reads and feeds it through the identical _classify_pickle_global allow/
# deny path. If this test ever fails again, INST has stopped being tracked.
# ---------------------------------------------------------------------------
def test_mfv_detects_inst_opcode_pickle_rce(tmp_path):
    """A hand-built protocol-0 pickle that calls os.system via the INST
    opcode (rather than GLOBAL/STACK_GLOBAL + REDUCE) must still be flagged."""
    # MARK, push "echo pwned", INST os/system (pops the mark-to-top args and
    # calls os.system("echo pwned") directly), STOP.
    data = b"(" + b"S'echo pwned'\n" + b"i" + b"os\nsystem\n" + b"."

    evil_path = tmp_path / "evil_inst.pkl"
    evil_path.write_bytes(data)

    findings = ModelFileScanner().scan_file(evil_path)

    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert critical, (
        "Expected a CRITICAL finding for the INST-opcode os.system() backdoor, "
        f"got: {[(f.rule_id, f.severity) for f in findings]}"
    )
    assert any("os.system" in f.message for f in critical), (
        f"Expected the finding to name os.system, got: {[f.message for f in critical]}"
    )

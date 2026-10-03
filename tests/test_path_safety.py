"""Tests that LLM-supplied file paths in hunt hypotheses can't escape target_path.

Hypotheses come from LLM JSON output -- untrusted input, whether from plain
hallucination or a prompt-injected source comment. _safe_resolve() is the
single guard that _verify_claim_context, _build_chain, and
_resolve_deepdive_files all route through before touching the filesystem.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from rowan.agents.workflow import HuntState, HuntWorkflow
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, Severity


def _workflow(tmp: Path) -> HuntWorkflow:
    config = ScanConfig(target=tmp, no_sca=True)
    llm = MagicMock()
    llm.is_configured = True
    llm._backend = "deepseek"
    state = HuntState(target_path=tmp, config=config, llm=llm)
    return HuntWorkflow(state)


class TestSafeResolve:
    def test_relative_path_inside_target_is_allowed(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        workflow = _workflow(tmp_path)
        result = workflow._safe_resolve(tmp_path, "app.py")
        assert result == tmp_path / "app.py"

    def test_absolute_path_outside_target_is_rejected(self, tmp_path):
        workflow = _workflow(tmp_path)
        assert workflow._safe_resolve(tmp_path, "/etc/passwd") is None

    def test_dotdot_escape_is_rejected(self, tmp_path):
        outside = tmp_path.parent / "secret.txt"
        outside.write_text("secret\n")
        workflow = _workflow(tmp_path)
        try:
            escape = f"../{outside.name}"
            assert workflow._safe_resolve(tmp_path, escape) is None
        finally:
            outside.unlink(missing_ok=True)

    def test_symlink_escape_is_rejected(self, tmp_path):
        outside_dir = Path(tempfile.mkdtemp())
        secret = outside_dir / "secret.txt"
        secret.write_text("super secret\n")
        link = tmp_path / "evil_link.py"
        link.symlink_to(secret)
        workflow = _workflow(tmp_path)
        assert workflow._safe_resolve(tmp_path, "evil_link.py") is None

    def test_empty_candidate_returns_none(self, tmp_path):
        workflow = _workflow(tmp_path)
        assert workflow._safe_resolve(tmp_path, "") is None

    def test_absolute_path_that_is_target_itself_is_allowed(self, tmp_path):
        (tmp_path / "app.py").write_text("x = 1\n")
        workflow = _workflow(tmp_path)
        absolute = str((tmp_path / "app.py").resolve())
        result = workflow._safe_resolve(tmp_path, absolute)
        assert result is not None


class TestVerifyClaimContextPathSafety:
    def test_hallucinated_absolute_path_not_read(self, tmp_path):
        """A verify-stage hypothesis with no matching surface finding must not
        read an arbitrary absolute path even if it exists on disk."""
        outside_dir = Path(tempfile.mkdtemp())
        secret = outside_dir / "id_rsa"
        secret.write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nsecret\n")

        workflow = _workflow(tmp_path)
        hypothesis = {
            "rule_id": "TEST-001",
            "file": str(secret),
            "line": 1,
            "exploitability": "confirmed",
            "attack_story": "hallucinated",
        }
        ctx = workflow._verify_claim_context(hypothesis)
        assert "secret" not in ctx["code_context"]
        assert ctx["code_context"] == "[[file outside scan target]]"

    def test_hallucinated_traversal_path_not_read(self, tmp_path):
        outside = tmp_path.parent / "not_yours.txt"
        outside.write_text("private data\n")
        try:
            workflow = _workflow(tmp_path)
            hypothesis = {
                "rule_id": "TEST-002",
                "file": f"../{outside.name}",
                "line": 1,
                "exploitability": "likely",
            }
            ctx = workflow._verify_claim_context(hypothesis)
            assert "private data" not in ctx["code_context"]
        finally:
            outside.unlink(missing_ok=True)

    def test_legit_path_under_target_still_read(self, tmp_path):
        (tmp_path / "app.py").write_text("import os\nos.system(x)\n")
        workflow = _workflow(tmp_path)
        hypothesis = {
            "rule_id": "TEST-003",
            "file": "app.py",
            "line": 2,
            "exploitability": "confirmed",
        }
        ctx = workflow._verify_claim_context(hypothesis)
        assert "os.system" in ctx["code_context"]


class TestBuildChainPathSafety:
    def test_absolute_path_outside_target_not_read_into_evidence(self, tmp_path):
        outside_dir = Path(tempfile.mkdtemp())
        secret = outside_dir / "credentials.json"
        secret.write_text('{"api_key": "super-secret-value"}\n')

        workflow = _workflow(tmp_path)
        hypothesis = {
            "rule_id": "TEST-RCE",
            "file": str(secret),
            "line": 1,
            "exploitability": "confirmed",
            "attack_story": "hallucinated chain",
        }
        chain = workflow._build_chain(hypothesis)
        assert chain is not None
        assert chain["evidence"] == []

    def test_legit_path_under_target_still_produces_evidence(self, tmp_path):
        (tmp_path / "vuln.py").write_text("\n".join(f"line{i}" for i in range(10)) + "\n")
        workflow = _workflow(tmp_path)
        hypothesis = {
            "rule_id": "TEST-RCE",
            "file": "vuln.py",
            "line": 5,
            "exploitability": "confirmed",
            "attack_story": "real chain",
        }
        chain = workflow._build_chain(hypothesis)
        assert chain is not None
        assert len(chain["evidence"]) > 0


class TestResolveDeepdiveFilesPathSafety:
    def test_absolute_path_outside_target_is_dropped(self, tmp_path):
        outside_dir = Path(tempfile.mkdtemp())
        secret = outside_dir / "config.py"
        secret.write_text("SECRET = 1\n")

        workflow = _workflow(tmp_path)
        resolved = workflow._resolve_deepdive_files({str(secret)})
        assert resolved == {}


class TestFindingWithContextPathSafety:
    """A Finding's file_path comes from an upstream scan pass, not from the
    LLM, so it was not routed through _safe_resolve the way a hypothesis-
    reported path is. If an upstream pass ever produces a Finding pointing
    outside target_path (e.g. via a symlink it failed to guard against,
    issue #226), _finding_with_context must not read that file's content and
    hand it to the LLM provider anyway.
    """

    def _finding(self, file_path: str) -> Finding:
        return Finding(
            rule_id="TEST-001",
            message="test finding",
            severity=Severity.HIGH,
            category=Category.INJECTION,
            file_path=file_path,
            start_line=1,
        )

    def test_finding_pointing_outside_target_is_not_read(self, tmp_path):
        outside_dir = Path(tempfile.mkdtemp())
        secret = outside_dir / "credentials.env"
        secret.write_text("PROD_DB_PASSWORD=hunter2\n")

        result = HuntWorkflow._finding_with_context(
            self._finding(str(secret)), target_path=tmp_path
        )
        assert "hunter2" not in result["code_context"]
        assert result["code_context"] == "[[file outside scan target]]"

    def test_finding_symlink_escape_is_not_read(self, tmp_path):
        outside_dir = Path(tempfile.mkdtemp())
        secret = outside_dir / "creds.env"
        secret.write_text("PROD_DB_PASSWORD=hunter2\n")
        link = tmp_path / "innocuous.py"
        link.symlink_to(secret)

        result = HuntWorkflow._finding_with_context(
            self._finding(str(link)), target_path=tmp_path
        )
        assert "hunter2" not in result["code_context"]

    def test_finding_inside_target_still_read(self, tmp_path):
        (tmp_path / "app.py").write_text("import os\nos.system(x)\n")
        result = HuntWorkflow._finding_with_context(
            self._finding(str(tmp_path / "app.py")), target_path=tmp_path
        )
        assert "os.system" in result["code_context"]

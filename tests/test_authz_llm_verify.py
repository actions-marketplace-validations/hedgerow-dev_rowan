"""Tests for AuthzPass LLM adjudication (#174, ADR-0003).

`HuntWorkflow.verify_authz_findings` is a filter on `AuthzPass`'s own
deterministic AUTHZ-BOLA-* candidate set (High/Medium only): refuted ->
dropped, uncertain -> kept at Medium, upheld -> promoted to High. With no LLM
backend configured it must be a pure passthrough -- byte-identical output, no
network calls. Every candidate shares the same rule_id ("AUTHZ-BOLA-001"), so
verdicts are matched back to findings by an explicit `_claim_idx`, never by
rule_id alone (unlike the general hunt hypotheses, which vary by rule_id).
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

from rowan.agents.workflow import (
    AUTHZ_VERIFY_PROMPT,
    AUTHZ_VERIFY_SYSTEM,
    HuntState,
    HuntWorkflow,
)
from rowan.config import ScanConfig
from rowan.core.confidence import AUTHZ_BOLA_HIGH, AUTHZ_BOLA_MEDIUM
from rowan.core.findings import Category, Finding, Severity


def _make_workflow(llm_configured: bool = True, backend: str = "deepseek") -> tuple[HuntWorkflow, HuntState]:
    with tempfile.TemporaryDirectory() as tmp:
        config = ScanConfig(target=Path(tmp), enable_authz=True)
        llm = MagicMock()
        llm.is_configured = llm_configured
        llm._backend = backend
        state = HuntState(target_path=Path(tmp), config=config, llm=llm)
        return HuntWorkflow(state), state


def _authz_finding(
    severity: Severity = Severity.HIGH,
    confidence: float = AUTHZ_BOLA_HIGH,
    line: int = 1,
    missing: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id="AUTHZ-BOLA-001",
        message="Handler 'detail' reads Document keyed by user-controlled input",
        severity=severity,
        category=Category.AUTH,
        file_path="views.py",
        start_line=line,
        confidence=confidence,
        cwe_ids=[639],
        engine="authz",
        metadata={"model": "Document", "missing_models": missing or ["ownership"]},
    )


class TestPassthrough:
    def test_llm_disabled_is_byte_identical_passthrough(self):
        workflow, state = _make_workflow(llm_configured=False)
        findings = [_authz_finding()]
        result = workflow.verify_authz_findings(findings)
        assert result == findings
        assert result[0] is findings[0]
        state.llm.generate_structured.assert_not_called()

    def test_no_authz_candidates_is_noop_no_network_call(self):
        workflow, state = _make_workflow(llm_configured=True)
        other = Finding(
            rule_id="TNT-001", message="x", severity=Severity.HIGH,
            category=Category.INJECTION, file_path="a.py", start_line=1,
        )
        result = workflow.verify_authz_findings([other])
        assert result == [other]
        state.llm.generate_structured.assert_not_called()

    def test_low_severity_authz_finding_untouched(self):
        # Only High/Medium AuthzPass findings are candidates for adjudication.
        workflow, state = _make_workflow(llm_configured=True)
        low = _authz_finding(severity=Severity.LOW, confidence=0.1)
        result = workflow.verify_authz_findings([low])
        assert result == [low]
        state.llm.generate_structured.assert_not_called()

    def test_non_authz_findings_pass_through_untouched(self):
        workflow, state = _make_workflow(llm_configured=True)
        other = Finding(
            rule_id="TNT-001", message="x", severity=Severity.HIGH,
            category=Category.INJECTION, file_path="a.py", start_line=1,
        )
        authz = _authz_finding()
        state.llm.generate_structured.return_value = {
            "verdicts": [{"_claim_idx": 0, "verdict": "upheld", "reason": "test"}]
        }
        result = workflow.verify_authz_findings([other, authz])
        assert other in result
        assert len(result) == 2


class TestVerdictApplication:
    def test_refuted_drops_the_finding(self):
        workflow, state = _make_workflow(llm_configured=True)
        finding = _authz_finding()
        state.llm.generate_structured.return_value = {
            "verdicts": [{"_claim_idx": 0, "verdict": "refuted", "reason": "owner check present"}]
        }
        assert workflow.verify_authz_findings([finding]) == []

    def test_uncertain_keeps_at_medium(self):
        workflow, state = _make_workflow(llm_configured=True)
        finding = _authz_finding(severity=Severity.HIGH, confidence=AUTHZ_BOLA_HIGH)
        state.llm.generate_structured.return_value = {
            "verdicts": [{"_claim_idx": 0, "verdict": "uncertain", "reason": "not enough context"}]
        }
        result = workflow.verify_authz_findings([finding])
        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM
        assert result[0].confidence == AUTHZ_BOLA_MEDIUM

    def test_uppercase_refuted_drops_the_finding(self):
        # BACKLOG HN-02
        workflow, state = _make_workflow(llm_configured=True)
        state.llm.generate_structured.return_value = {
            "verdicts": [{"_claim_idx": 0, "verdict": "Refuted", "reason": "r"}]
        }
        assert workflow.verify_authz_findings([_authz_finding()]) == []

    def test_unknown_verdict_keeps_at_medium(self):
        # BACKLOG HN-02: anything but an exact upheld is uncertain, not upheld.
        workflow, state = _make_workflow(llm_configured=True)
        finding = _authz_finding(severity=Severity.HIGH, confidence=AUTHZ_BOLA_HIGH)
        state.llm.generate_structured.return_value = {
            "verdicts": [{"_claim_idx": 0, "verdict": "maybe", "reason": "r"}]
        }
        result = workflow.verify_authz_findings([finding])
        assert len(result) == 1 and result[0].severity == Severity.MEDIUM

    def test_upheld_promotes_medium_to_high(self):
        workflow, state = _make_workflow(llm_configured=True)
        finding = _authz_finding(severity=Severity.MEDIUM, confidence=AUTHZ_BOLA_MEDIUM)
        state.llm.generate_structured.return_value = {
            "verdicts": [{"_claim_idx": 0, "verdict": "upheld", "reason": "no check on any path"}]
        }
        result = workflow.verify_authz_findings([finding])
        assert len(result) == 1
        assert result[0].severity == Severity.HIGH
        assert result[0].confidence == AUTHZ_BOLA_HIGH

    def test_missing_verdict_defaults_to_uncertain(self):
        # The model dropped this claim from its response entirely.
        workflow, state = _make_workflow(llm_configured=True)
        finding = _authz_finding(severity=Severity.HIGH, confidence=AUTHZ_BOLA_HIGH)
        state.llm.generate_structured.return_value = {"verdicts": []}
        result = workflow.verify_authz_findings([finding])
        assert len(result) == 1
        assert result[0].severity == Severity.MEDIUM


class TestClaimIndexing:
    """Every candidate shares rule_id "AUTHZ-BOLA-001", so verdicts must be
    matched by _claim_idx, not rule_id -- unlike the general hunt verify
    node's hypotheses, which vary by rule_id."""

    def test_multiple_candidates_same_rule_id_matched_by_claim_idx(self):
        workflow, state = _make_workflow(llm_configured=True)
        findings = [_authz_finding(line=i) for i in range(1, 4)]

        def fake_generate_structured(prompt, **kwargs):
            claims = json.loads(
                prompt.split("Candidates:\n", 1)[1].split("\n\nReturn:", 1)[0]
            )
            return {
                "verdicts": [
                    {
                        "_claim_idx": c["_claim_idx"],
                        "verdict": "refuted" if c["_claim_idx"] == 1 else "upheld",
                        "reason": "test",
                    }
                    for c in claims
                ]
            }

        state.llm.generate_structured.side_effect = fake_generate_structured
        result = workflow.verify_authz_findings(findings)

        # Only the middle candidate (_claim_idx 1) was refuted -> dropped.
        assert len(result) == 2
        assert {f.start_line for f in result} == {1, 3}
        assert all(f.severity == Severity.HIGH for f in result)

    def test_batches_split_across_multiple_llm_calls_index_globally(self):
        # ollama's batch size is 4 -- 5 candidates forces 2 calls; the second
        # batch's claims must carry global indices (4), not local ones (0).
        workflow, state = _make_workflow(llm_configured=True, backend="ollama")
        findings = [_authz_finding(line=i) for i in range(5)]

        def fake_generate_structured(prompt, **kwargs):
            claims = json.loads(
                prompt.split("Candidates:\n", 1)[1].split("\n\nReturn:", 1)[0]
            )
            return {
                "verdicts": [
                    {
                        "_claim_idx": c["_claim_idx"],
                        "verdict": "refuted" if c["_claim_idx"] == 4 else "upheld",
                        "reason": "test",
                    }
                    for c in claims
                ]
            }

        state.llm.generate_structured.side_effect = fake_generate_structured
        result = workflow.verify_authz_findings(findings)

        assert state.llm.generate_structured.call_count == 2
        assert len(result) == 4
        assert {f.start_line for f in result} == {0, 1, 2, 3}

    def test_llm_call_count_scales_with_candidates_not_files(self):
        # ADR-0003: "one call per candidate [batch], not per file" -- 8
        # candidates at ollama's batch size of 4 is exactly 2 calls,
        # independent of how many distinct files they came from.
        workflow, state = _make_workflow(llm_configured=True, backend="ollama")
        findings = [
            _authz_finding(line=i) for i in range(8)
        ]
        for i, f in enumerate(findings):
            f.file_path = f"file_{i}.py"
        state.llm.generate_structured.return_value = {"verdicts": []}
        workflow.verify_authz_findings(findings)
        assert state.llm.generate_structured.call_count == 2


class TestHallucinationGuards:
    def test_system_prompt_forbids_fabrication(self):
        assert "fabricate" in AUTHZ_VERIFY_SYSTEM.lower()
        assert "code_context is authoritative" in AUTHZ_VERIFY_SYSTEM.lower()

    def test_prompt_template_references_code_context_and_missing_models(self):
        assert "code_context" in AUTHZ_VERIFY_PROMPT or "claims_json" in AUTHZ_VERIFY_PROMPT
        assert "missing_models" in AUTHZ_VERIFY_PROMPT

"""Tests for EnrichmentPass._merge_duplicate_rule_groups /
_merge_duplicate_cluster (cross-rule-id duplicate finding merge).

A single vulnerable line (e.g. ``torch.load(name)``) can trigger findings
from multiple DIFFERENT rule_ids whose regex patterns detect the exact same
underlying condition (see _DUPLICATE_RULE_GROUPS in
rowan/passes/enrichment.py), often with contradictory severities (one
HIGH, one MEDIUM) for what a human reading the report sees as one
vulnerability. This merge step collapses those into a single survivor
finding, recording every collapsed rule_id in
``metadata["duplicate_rule_ids"]``.

Covers:
  1. Basic same-group, near-line merge picks the better (lower-ranked)
     severity.
  2. The disabled-rule survivor guard: a thresholds.yaml `enabled: false`
     rule_id must never be picked as merge survivor even when it would win
     a plain lexicographic tiebreak, because _apply_thresholds (the very
     next pipeline step) would otherwise delete the whole merged finding.
  3. Findings in different (or no) duplicate groups never merge.
  4. Findings more than 2 lines apart never merge, even in the same group.
  5. Findings in different files never merge, even same group/same line.
  6. Corpus-consistency guard: every rule_id referenced by
     _DUPLICATE_RULE_GROUPS actually exists in rules/converted/_manifest.json.

Deliberately uses tempfile.NamedTemporaryFile (with the OS default temp
directory) rather than pytest's `tmp_path` fixture: `tmp_path` embeds the
test function's own name into the generated directory path (e.g.
".../test_two_group_members_merge_to_better_severity0/..."), and since
every test name here starts with "test_", EnrichmentPass._is_test_path
(which tokenizes every path segment on [-_.] and checks for a literal
"test" token) misclassifies the finding's file as being in a test
directory -- silently downgrading HIGH to MEDIUM and attaching
metadata["test_context"] before the merge step under test ever runs. That
is exactly the "unrelated suppressor eats the finding for the wrong
reason" trap called out for this test file; using NamedTemporaryFile's
default (non-"test"-prefixed) temp path avoids it.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import yaml

from rowan.config import ScanConfig
from rowan.core.findings import (
    Category,
    Finding,
    ScanResult,
    Severity,
    TaintFlow,
    TaintNode,
)
from rowan.passes.enrichment import _DUPLICATE_RULE_GROUPS, EnrichmentPass

_REPO_ROOT = Path(__file__).resolve().parent.parent
_MANIFEST_PATH = _REPO_ROOT / "rules" / "converted" / "_manifest.json"

# A plausible torch-checkpoint-loading file. All rule_ids used across these
# tests are AI/deserialization rules, so the file carries a real "import
# torch" -- without it, EnrichmentPass._suppress_ai_on_non_ai would gate any
# ns-aiml-* finding down to severity=INFO before the merge step ever runs,
# for a reason that has nothing to do with what this test is verifying.
# File-level context (imports, the @app.route decorator) does NOT promote a
# pattern-only deserialization finding: _cap_unverified_severity now caps any
# dataflow-claim finding with no taint_flow of its own to MEDIUM, because
# evidence tiers describe the finding, not the surrounding file. A test that
# needs a finding to survive enrichment at HIGH must therefore give that
# finding its own taint_flow (see test_two_group_members_merge_to_better_
# severity), which is the only thing that legitimately keeps it above the cap.
_TORCH_FILE_CONTENT = (
    "import torch\n"
    "\n"
    "\n"
    "@app.route('/load')\n"
    "def load_checkpoint(path):\n"
    "    model = torch.load(path)\n"
    "    return model\n"
    "\n"
    "\n"
    "def load_other(path):\n"
    "    model2 = torch.load(path)\n"
    "    return model2\n"
)


def _write_torch_file() -> str:
    """Write _TORCH_FILE_CONTENT to a fresh NamedTemporaryFile and return
    its path. Caller is responsible for unlinking it."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False, encoding="utf-8"
    ) as fh:
        fh.write(_TORCH_FILE_CONTENT)
        return fh.name


def _run_enrichment(findings: list[Finding]) -> list[Finding]:
    ctx = type("Ctx", (), {
        "target_path": Path("."),
        "config": ScanConfig(target=Path(".")),
        "result": ScanResult(findings=findings),
        "metadata": {},
    })()
    EnrichmentPass().run(ctx)
    return ctx.result.findings


def _make_finding(
    rule_id: str, severity: Severity, file_path: str, start_line: int,
    category: Category = Category.DESERIALIZATION, confidence: float = 0.8,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"{rule_id} unsafe torch.load without weights_only",
        severity=severity,
        category=category,
        file_path=file_path,
        start_line=start_line,
        engine="opengrep",
        confidence=confidence,
    )


class TestBasicCrossRuleMerge:
    def test_two_group_members_merge_to_better_severity(self):
        """NS-DESER-002 and ns-aiml-030 are both in the torch.load
        duplicate group. Same file, lines within 2 of each other, different
        severities -- must collapse to a single finding carrying the
        better (HIGH, not MEDIUM) severity and both rule_ids recorded.

        NS-DESER-002 carries its own taint_flow (request arg -> torch.load
        sink), which is what legitimately keeps it at HIGH through
        _cap_unverified_severity; ns-aiml-030 is pattern-only and rides in
        at MEDIUM. The merge must still pick the better (HIGH) severity."""
        fp = _write_torch_file()
        traced = _make_finding("NS-DESER-002", Severity.HIGH, fp, 5)
        traced.taint_flow = TaintFlow(
            source=TaintNode(file_path=fp, line=5, snippet="path = request.args.get('path')"),
            sink=TaintNode(file_path=fp, line=5, snippet="torch.load(path)"),
        )
        try:
            findings = [
                traced,
                _make_finding("ns-aiml-030", Severity.MEDIUM, fp, 5),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(fp).unlink(missing_ok=True)

        assert len(result) == 1, (
            f"expected exactly one surviving finding, got {len(result)}: "
            f"{[(f.rule_id, f.severity) for f in result]}"
        )
        survivor = result[0]
        assert survivor.severity == Severity.HIGH
        assert survivor.metadata.get("duplicate_rule_ids") == [
            "NS-DESER-002", "ns-aiml-030",
        ]


class TestDisabledRuleSurvivorGuard:
    def test_disabled_rule_id_not_picked_as_survivor(self):
        """NS-DESER-006 and ns-aiml-030 are group-mates (torch.load group)
        with TIED severity. NS-DESER-006 is `enabled: false` in the real
        config/thresholds.yaml, and lexicographically "NS-DESER-006" sorts
        before "ns-aiml-030" (uppercase < lowercase in ASCII) -- so a plain
        lexicographic tiebreak would wrongly pick NS-DESER-006 as survivor,
        and _apply_thresholds (which runs immediately after the merge step
        in EnrichmentPass.run()) would then silently delete the whole
        merged finding, losing ns-aiml-030's legitimate signal too.

        The guard in _merge_duplicate_cluster must disqualify a
        thresholds.yaml-disabled rule_id from being picked as survivor, so
        the actual survivor here must be ns-aiml-030, and a finding must
        still be present after the full run() -- i.e. _apply_thresholds did
        NOT delete it.
        """
        fp = _write_torch_file()
        try:
            findings = [
                _make_finding("NS-DESER-006", Severity.HIGH, fp, 5),
                _make_finding("ns-aiml-030", Severity.HIGH, fp, 5),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(fp).unlink(missing_ok=True)

        assert len(result) == 1, (
            "the merged finding must survive _apply_thresholds -- got "
            f"{len(result)} findings: {[(f.rule_id, f.severity) for f in result]}"
        )
        survivor = result[0]
        assert survivor.rule_id == "ns-aiml-030", (
            "disabled rule_id NS-DESER-006 was picked as merge survivor "
            f"instead of ns-aiml-030 (actual survivor rule_id: {survivor.rule_id!r}); "
            "the disabled-rule survivor guard did not disqualify it"
        )
        assert survivor.metadata.get("duplicate_rule_ids") == [
            "NS-DESER-006", "ns-aiml-030",
        ]


class TestNoFalseMergeAcrossGroups:
    def test_different_groups_do_not_merge(self):
        """NS-DESER-002 (torch.load group) and ns-aiml-032 (np.load/pandas
        allow_pickle group) are DIFFERENT duplicate groups -- same file,
        same line must NOT collapse them."""
        fp = _write_torch_file()
        try:
            findings = [
                _make_finding("NS-DESER-002", Severity.HIGH, fp, 5),
                _make_finding("ns-aiml-032", Severity.HIGH, fp, 5),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(fp).unlink(missing_ok=True)

        assert len(result) == 2
        rule_ids = {f.rule_id for f in result}
        assert rule_ids == {"NS-DESER-002", "ns-aiml-032"}
        for f in result:
            assert "duplicate_rule_ids" not in f.metadata

    def test_rule_in_no_group_does_not_merge(self):
        """A rule_id that appears in NO _DUPLICATE_RULE_GROUPS entry must
        never be merged with anything, even a real group member on the
        same file/line."""
        fp = _write_torch_file()
        try:
            findings = [
                _make_finding("NS-DESER-002", Severity.HIGH, fp, 5),
                _make_finding("UNRELATED-RULE-001", Severity.HIGH, fp, 5),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(fp).unlink(missing_ok=True)

        assert len(result) == 2
        rule_ids = {f.rule_id for f in result}
        assert rule_ids == {"NS-DESER-002", "UNRELATED-RULE-001"}
        for f in result:
            assert "duplicate_rule_ids" not in f.metadata


class TestLineWindowBoundary:
    def test_findings_more_than_two_lines_apart_do_not_merge(self):
        """Same group, same file, but start_line more than 2 apart (5
        lines, in this case) -- must NOT merge, both survive separately."""
        fp = _write_torch_file()
        try:
            findings = [
                _make_finding("NS-DESER-002", Severity.HIGH, fp, 5),
                _make_finding("ns-aiml-030", Severity.MEDIUM, fp, 10),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(fp).unlink(missing_ok=True)

        assert len(result) == 2
        rule_ids = {f.rule_id for f in result}
        assert rule_ids == {"NS-DESER-002", "ns-aiml-030"}
        for f in result:
            assert "duplicate_rule_ids" not in f.metadata


class TestDifferentFilesNeverMerge:
    def test_same_group_same_line_different_files_do_not_merge(self):
        """Same duplicate group, same line number, but different
        file_path -- must never merge across files."""
        fp_a = _write_torch_file()
        fp_b = _write_torch_file()
        try:
            findings = [
                _make_finding("NS-DESER-002", Severity.HIGH, fp_a, 5),
                _make_finding("ns-aiml-030", Severity.MEDIUM, fp_b, 5),
            ]
            result = _run_enrichment(findings)
        finally:
            Path(fp_a).unlink(missing_ok=True)
            Path(fp_b).unlink(missing_ok=True)

        assert len(result) == 2
        rule_ids = {f.rule_id for f in result}
        assert rule_ids == {"NS-DESER-002", "ns-aiml-030"}
        for f in result:
            assert "duplicate_rule_ids" not in f.metadata


class TestDuplicateGroupsCorpusConsistency:
    def test_all_grouped_rule_ids_exist_in_manifest(self):
        """Cheap guard against _DUPLICATE_RULE_GROUPS silently going stale
        if a referenced rule_id is later renamed or removed from the
        corpus: every rule_id appearing in any _DUPLICATE_RULE_GROUPS entry
        must exist as an `id` in rules/converted/_manifest.json."""
        manifest = json.loads(_MANIFEST_PATH.read_text(encoding="utf-8"))
        known_rule_ids = {r["id"] for r in manifest["rules"]}
        for path in (_REPO_ROOT / "rules").glob("*_taint.yaml"):
            known_rule_ids.update(
                rule["id"]
                for rule in (yaml.safe_load(path.read_text(encoding="utf-8")) or {}).get(
                    "rules", []
                )
            )

        all_grouped_ids = {
            rule_id for group in _DUPLICATE_RULE_GROUPS for rule_id in group
        }
        missing = all_grouped_ids - known_rule_ids
        assert not missing, (
            f"_DUPLICATE_RULE_GROUPS references rule_id(s) not present in "
            f"the manifest (renamed/removed from the corpus?): {sorted(missing)}"
        )

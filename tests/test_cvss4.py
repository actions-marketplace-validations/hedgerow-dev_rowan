"""CVSS v4.0 scoring (SC-15), checked against FIRST's reference calculator."""

from __future__ import annotations

import json
from pathlib import Path

from rowan.core.findings import Severity
from rowan.cvss4 import base_score
from rowan.passes.sca import SCAPass

_FIXTURE = Path(__file__).parent / "fixtures" / "cvss4_reference_scores.json"


def test_matches_reference_calculator():
    scores = json.loads(_FIXTURE.read_text(encoding="utf-8"))["scores"]
    mismatches = {v: (ref, base_score(v)) for v, ref in scores.items() if base_score(v) != ref}
    assert len(scores) > 1000
    assert mismatches == {}


def test_invalid_vectors_are_not_scored():
    assert base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") is None
    assert base_score("CVSS:4.0/AV:N/AC:L") is None  # missing base metrics
    assert base_score("CVSS:4.0/AV:Q/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None
    assert base_score("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:S/SA:N") is None


def test_cvss4_critical_mapped():
    """SC-15: a CVSS-4-only critical advisory was MEDIUM by default."""
    vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    assert SCAPass._cvss_base_score(vector) == 9.3
    advisory = {"severity": [{"type": "CVSS_V4", "score": vector}]}
    assert SCAPass()._map_osv_severity(advisory) == Severity.CRITICAL


def test_cvss3_entry_still_wins_when_both_are_present():
    advisory = {"severity": [
        {"type": "CVSS_V4", "score": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
        {"type": "CVSS_V3", "score": "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
    ]}
    assert SCAPass()._map_osv_severity(advisory) == Severity.LOW

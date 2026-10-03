"""CVSS v4.0 base score, ported from FIRST's reference calculator.

Source: https://github.com/FIRSTdotorg/cvss-v4-calculator (cvss_score.js,
cvss_lookup.js, max_composed.js, max_severity.js), BSD-2-Clause. The tables
below were generated from those files, not retyped; ``tests/test_cvss4.py``
checks this port against the reference JavaScript. Used by SC-15 so a
CVSS-4-only advisory is not scored MEDIUM by default.
"""

# Copyright (c) 2023 FIRST.ORG, Inc., Red Hat, and contributors
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

from __future__ import annotations

import math

# MacroVector -> score (cvss_lookup.js).
_LOOKUP: dict[str, float] = {
    "000000": 10.0, "000001": 9.9, "000010": 9.8, "000011": 9.5, "000020": 9.5, "000021": 9.2,
    "000100": 10.0, "000101": 9.6, "000110": 9.3, "000111": 8.7, "000120": 9.1, "000121": 8.1,
    "000200": 9.3, "000201": 9.0, "000210": 8.9, "000211": 8.0, "000220": 8.1, "000221": 6.8,
    "001000": 9.8, "001001": 9.5, "001010": 9.5, "001011": 9.2, "001020": 9.0, "001021": 8.4,
    "001100": 9.3, "001101": 9.2, "001110": 8.9, "001111": 8.1, "001120": 8.1, "001121": 6.5,
    "001200": 8.8, "001201": 8.0, "001210": 7.8, "001211": 7.0, "001220": 6.9, "001221": 4.8,
    "002001": 9.2, "002011": 8.2, "002021": 7.2, "002101": 7.9, "002111": 6.9, "002121": 5.0,
    "002201": 6.9, "002211": 5.5, "002221": 2.7, "010000": 9.9, "010001": 9.7, "010010": 9.5,
    "010011": 9.2, "010020": 9.2, "010021": 8.5, "010100": 9.5, "010101": 9.1, "010110": 9.0,
    "010111": 8.3, "010120": 8.4, "010121": 7.1, "010200": 9.2, "010201": 8.1, "010210": 8.2,
    "010211": 7.1, "010220": 7.2, "010221": 5.3, "011000": 9.5, "011001": 9.3, "011010": 9.2,
    "011011": 8.5, "011020": 8.5, "011021": 7.3, "011100": 9.2, "011101": 8.2, "011110": 8.0,
    "011111": 7.2, "011120": 7.0, "011121": 5.9, "011200": 8.4, "011201": 7.0, "011210": 7.1,
    "011211": 5.2, "011220": 5.0, "011221": 3.0, "012001": 8.6, "012011": 7.5, "012021": 5.2,
    "012101": 7.1, "012111": 5.2, "012121": 2.9, "012201": 6.3, "012211": 2.9, "012221": 1.7,
    "100000": 9.8, "100001": 9.5, "100010": 9.4, "100011": 8.7, "100020": 9.1, "100021": 8.1,
    "100100": 9.4, "100101": 8.9, "100110": 8.6, "100111": 7.4, "100120": 7.7, "100121": 6.4,
    "100200": 8.7, "100201": 7.5, "100210": 7.4, "100211": 6.3, "100220": 6.3, "100221": 4.9,
    "101000": 9.4, "101001": 8.9, "101010": 8.8, "101011": 7.7, "101020": 7.6, "101021": 6.7,
    "101100": 8.6, "101101": 7.6, "101110": 7.4, "101111": 5.8, "101120": 5.9, "101121": 5.0,
    "101200": 7.2, "101201": 5.7, "101210": 5.7, "101211": 5.2, "101220": 5.2, "101221": 2.5,
    "102001": 8.3, "102011": 7.0, "102021": 5.4, "102101": 6.5, "102111": 5.8, "102121": 2.6,
    "102201": 5.3, "102211": 2.1, "102221": 1.3, "110000": 9.5, "110001": 9.0, "110010": 8.8,
    "110011": 7.6, "110020": 7.6, "110021": 7.0, "110100": 9.0, "110101": 7.7, "110110": 7.5,
    "110111": 6.2, "110120": 6.1, "110121": 5.3, "110200": 7.7, "110201": 6.6, "110210": 6.8,
    "110211": 5.9, "110220": 5.2, "110221": 3.0, "111000": 8.9, "111001": 7.8, "111010": 7.6,
    "111011": 6.7, "111020": 6.2, "111021": 5.8, "111100": 7.4, "111101": 5.9, "111110": 5.7,
    "111111": 5.7, "111120": 4.7, "111121": 2.3, "111200": 6.1, "111201": 5.2, "111210": 5.7,
    "111211": 2.9, "111220": 2.4, "111221": 1.6, "112001": 7.1, "112011": 5.9, "112021": 3.0,
    "112101": 5.8, "112111": 2.6, "112121": 1.5, "112201": 2.3, "112211": 1.3, "112221": 0.6,
    "200000": 9.3, "200001": 8.7, "200010": 8.6, "200011": 7.2, "200020": 7.5, "200021": 5.8,
    "200100": 8.6, "200101": 7.4, "200110": 7.4, "200111": 6.1, "200120": 5.6, "200121": 3.4,
    "200200": 7.0, "200201": 5.4, "200210": 5.2, "200211": 4.0, "200220": 4.0, "200221": 2.2,
    "201000": 8.5, "201001": 7.5, "201010": 7.4, "201011": 5.5, "201020": 6.2, "201021": 5.1,
    "201100": 7.2, "201101": 5.7, "201110": 5.5, "201111": 4.1, "201120": 4.6, "201121": 1.9,
    "201200": 5.3, "201201": 3.6, "201210": 3.4, "201211": 1.9, "201220": 1.9, "201221": 0.8,
    "202001": 6.4, "202011": 5.1, "202021": 2.0, "202101": 4.7, "202111": 2.1, "202121": 1.1,
    "202201": 2.4, "202211": 0.9, "202221": 0.4, "210000": 8.8, "210001": 7.5, "210010": 7.3,
    "210011": 5.3, "210020": 6.0, "210021": 5.0, "210100": 7.3, "210101": 5.5, "210110": 5.9,
    "210111": 4.0, "210120": 4.1, "210121": 2.0, "210200": 5.4, "210201": 4.3, "210210": 4.5,
    "210211": 2.2, "210220": 2.0, "210221": 1.1, "211000": 7.5, "211001": 5.5, "211010": 5.8,
    "211011": 4.5, "211020": 4.0, "211021": 2.1, "211100": 6.1, "211101": 5.1, "211110": 4.8,
    "211111": 1.8, "211120": 2.0, "211121": 0.9, "211200": 4.6, "211201": 1.8, "211210": 1.7,
    "211211": 0.7, "211220": 0.8, "211221": 0.2, "212001": 5.3, "212011": 2.4, "212021": 1.4,
    "212101": 2.4, "212111": 1.2, "212121": 0.5, "212201": 1.0, "212211": 0.3, "212221": 0.1,
}

# Highest-severity vectors per EQ level (max_composed.js).
_MAX_COMPOSED = {'eq1': {'0': ['AV:N/PR:N/UI:N/'],
         '1': ['AV:A/PR:N/UI:N/', 'AV:N/PR:L/UI:N/', 'AV:N/PR:N/UI:P/'],
         '2': ['AV:P/PR:N/UI:N/', 'AV:A/PR:L/UI:P/']},
 'eq2': {'0': ['AC:L/AT:N/'], '1': ['AC:H/AT:N/', 'AC:L/AT:P/']},
 'eq3': {'0': {'0': ['VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/'],
               '1': ['VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/', 'VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/']},
         '1': {'0': ['VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/', 'VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/'],
               '1': ['VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/',
                     'VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/',
                     'VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/',
                     'VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/',
                     'VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/']},
         '2': {'1': ['VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/']}},
 'eq4': {'0': ['SC:H/SI:S/SA:S/'], '1': ['SC:H/SI:H/SA:H/'], '2': ['SC:L/SI:L/SA:L/']},
 'eq5': {'0': ['E:A/'], '1': ['E:P/'], '2': ['E:U/']}}

# Depth of each EQ level, in 0.1 steps (max_severity.js).
_MAX_SEVERITY = {'eq1': {'0': 1, '1': 4, '2': 5},
 'eq2': {'0': 1, '1': 2},
 'eq3eq6': {'0': {'0': 7, '1': 6}, '1': {'0': 8, '1': 8}, '2': {'1': 10}},
 'eq4': {'0': 6, '1': 5, '2': 4},
 'eq5': {'0': 1, '1': 1, '2': 1}}

_LEVELS = {
    "AV": {"N": 0.0, "A": 0.1, "L": 0.2, "P": 0.3},
    "PR": {"N": 0.0, "L": 0.1, "H": 0.2},
    "UI": {"N": 0.0, "P": 0.1, "A": 0.2},
    "AC": {"L": 0.0, "H": 0.1},
    "AT": {"N": 0.0, "P": 0.1},
    "VC": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VI": {"H": 0.0, "L": 0.1, "N": 0.2},
    "VA": {"H": 0.0, "L": 0.1, "N": 0.2},
    "SC": {"H": 0.1, "L": 0.2, "N": 0.3},
    "SI": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "SA": {"S": 0.0, "H": 0.1, "L": 0.2, "N": 0.3},
    "CR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "IR": {"H": 0.0, "M": 0.1, "L": 0.2},
    "AR": {"H": 0.0, "M": 0.1, "L": 0.2},
}
_BASE_METRICS = ("AV", "AC", "AT", "PR", "UI", "VC", "VI", "VA", "SC", "SI", "SA")
_BASE_VALUES = {metric: set(_LEVELS[metric]) for metric in _BASE_METRICS}
_BASE_VALUES["SI"] = _BASE_VALUES["SA"] = {"H", "L", "N"}  # S is environmental-only
_BASE_VALUES["SC"] = {"H", "L", "N"}


def _metric(selected: dict[str, str], metric: str) -> str:
    """The effective value of ``metric`` (cvss_score.js ``m``)."""
    value = selected.get(metric, "X")
    if metric == "E" and value == "X":
        return "A"
    if metric in ("CR", "IR", "AR") and value == "X":
        return "H"
    modified = selected.get("M" + metric)
    if modified is not None and modified != "X":
        return modified
    return value


def _macro_vector(selected: dict[str, str]) -> str:
    m = lambda metric: _metric(selected, metric)  # noqa: E731
    if m("AV") == "N" and m("PR") == "N" and m("UI") == "N":
        eq1 = "0"
    elif (m("AV") == "N" or m("PR") == "N" or m("UI") == "N") and m("AV") != "P":
        eq1 = "1"
    else:
        eq1 = "2"
    eq2 = "0" if m("AC") == "L" and m("AT") == "N" else "1"
    if m("VC") == "H" and m("VI") == "H":
        eq3 = "0"
    elif m("VC") == "H" or m("VI") == "H" or m("VA") == "H":
        eq3 = "1"
    else:
        eq3 = "2"
    if m("MSI") == "S" or m("MSA") == "S":
        eq4 = "0"
    elif m("SC") == "H" or m("SI") == "H" or m("SA") == "H":
        eq4 = "1"
    else:
        eq4 = "2"
    eq5 = {"A": "0", "P": "1", "U": "2"}[m("E")]
    if (
        (m("CR") == "H" and m("VC") == "H")
        or (m("IR") == "H" and m("VI") == "H")
        or (m("AR") == "H" and m("VA") == "H")
    ):
        eq6 = "0"
    else:
        eq6 = "1"
    return eq1 + eq2 + eq3 + eq4 + eq5 + eq6


def _vector_value(vector: str, metric: str) -> str:
    """cvss_score.js ``extractValueMetric``: first ``metric:`` in the string."""
    rest = vector[vector.index(metric) + len(metric) + 1:]
    return rest[: rest.index("/")] if rest.find("/") > 0 else rest


def _score(selected: dict[str, str]) -> float:
    """cvss_score.js ``cvss_score``, step for step (same float operations)."""
    m = lambda metric: _metric(selected, metric)  # noqa: E731
    if all(m(metric) == "N" for metric in ("VC", "VI", "VA", "SC", "SI", "SA")):
        return 0.0

    macro = _macro_vector(selected)
    value = _LOOKUP[macro]
    eq1, eq2, eq3, eq4, eq5, eq6 = (int(c) for c in macro)

    def lower(d1=0, d2=0, d3=0, d4=0, d5=0, d6=0) -> float | None:
        return _LOOKUP.get(f"{eq1 + d1}{eq2 + d2}{eq3 + d3}{eq4 + d4}{eq5 + d5}{eq6 + d6}")

    score_eq1 = lower(d1=1)
    score_eq2 = lower(d2=1)
    if eq3 == 0 and eq6 == 0:
        left, right = lower(d6=1), lower(d3=1)
        # JS: `left > right` is false when either is undefined.
        score_eq3eq6 = left if left is not None and right is not None and left > right else right
    elif eq3 == 1 and eq6 == 0:
        score_eq3eq6 = lower(d6=1)
    elif eq6 == 1 and eq3 in (0, 1):
        score_eq3eq6 = lower(d3=1)
    else:
        score_eq3eq6 = lower(d3=1, d6=1)
    score_eq4 = lower(d4=1)
    score_eq5 = lower(d5=1)

    maxes = [
        a + b + c + d + e
        for a in _MAX_COMPOSED["eq1"][str(eq1)]
        for b in _MAX_COMPOSED["eq2"][str(eq2)]
        for c in _MAX_COMPOSED["eq3"][str(eq3)][str(eq6)]
        for d in _MAX_COMPOSED["eq4"][str(eq4)]
        for e in _MAX_COMPOSED["eq5"][str(eq5)]
    ]
    distance: dict[str, float] = {}
    for max_vector in maxes:
        distance = {
            metric: levels[m(metric)] - levels[_vector_value(max_vector, metric)]
            for metric, levels in _LEVELS.items()
        }
        if not any(d < 0 for d in distance.values()):
            break

    current_eq1 = distance["AV"] + distance["PR"] + distance["UI"]
    current_eq2 = distance["AC"] + distance["AT"]
    current_eq3eq6 = (
        distance["VC"] + distance["VI"] + distance["VA"]
        + distance["CR"] + distance["IR"] + distance["AR"]
    )
    current_eq4 = distance["SC"] + distance["SI"] + distance["SA"]

    step = 0.1
    max_eq1 = _MAX_SEVERITY["eq1"][str(eq1)] * step
    max_eq2 = _MAX_SEVERITY["eq2"][str(eq2)] * step
    max_eq3eq6 = _MAX_SEVERITY["eq3eq6"][str(eq3)][str(eq6)] * step
    max_eq4 = _MAX_SEVERITY["eq4"][str(eq4)] * step

    existing = 0
    normalized = [0.0, 0.0, 0.0, 0.0, 0.0]
    for index, (lower_score, current, depth) in enumerate((
        (score_eq1, current_eq1, max_eq1),
        (score_eq2, current_eq2, max_eq2),
        (score_eq3eq6, current_eq3eq6, max_eq3eq6),
        (score_eq4, current_eq4, max_eq4),
    )):
        if lower_score is not None:
            existing += 1
            normalized[index] = (value - lower_score) * (current / depth)
    if score_eq5 is not None:
        existing += 1  # EQ5's proportion is always 0
        normalized[4] = (value - score_eq5) * 0

    mean = 0 if existing == 0 else (
        normalized[0] + normalized[1] + normalized[2] + normalized[3] + normalized[4]
    ) / existing
    value -= mean
    value = min(max(value, 0.0), 10.0)
    return math.floor(value * 10 + 0.5) / 10  # JS Math.round: half up


def base_score(vector: str) -> float | None:
    """Score a ``CVSS:4.0/...`` vector, or None if it is not a valid one."""
    parts = vector.strip().split("/")
    if not parts or parts[0] != "CVSS:4.0":
        return None
    selected: dict[str, str] = {}
    for part in parts[1:]:
        metric, sep, value = part.partition(":")
        if not sep or metric in selected:
            return None
        selected[metric] = value
    for metric in _BASE_METRICS:
        if selected.get(metric) not in _BASE_VALUES[metric]:
            return None
    if selected.get("E", "X") not in ("X", "A", "P", "U"):
        return None
    for metric in ("CR", "IR", "AR"):
        if selected.get(metric, "X") not in ("X", "H", "M", "L"):
            return None
    for metric in _BASE_METRICS:
        modified = selected.get("M" + metric)
        if modified is not None and modified != "X" and modified not in _LEVELS[metric]:
            return None
    return _score(selected)

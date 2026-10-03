"""Minimal version-range parsing/comparison for SCA (GitHub issue #80).

OSV's querybatch endpoint expects an exact version to check against a
package's affected ranges -- it isn't a range solver. When a manifest (not a
lockfile) only pins a range (`>=1.0`, `^2.0.0`), submitting that raw string
as `version` doesn't do anything meaningful; OSV either ignores it or the
match is silently wrong. This module gives just enough range comparison to
tell whether a manifest-only *range* spec could plausibly overlap a known
vulnerable range for the two ecosystems the SCA transitive-dependency
acceptance criteria are scoped to (pip, npm) -- not a full semver/PEP 440
solver.
"""

from __future__ import annotations

import re

_PRERELEASE_RE = re.compile(r"^(?:-|[.]?(?:a|b|c|rc|alpha|beta|pre|preview|dev)\d*)", re.IGNORECASE)


def parse_version_tuple(version: str) -> tuple[int, ...] | None:
    """Parse a dotted numeric version into a comparable tuple.

    A pre-release (`2.0.0rc1`, `1.2.3-beta.1`, a Go pseudo-version) gets a
    trailing -1 so it sorts below its release; build metadata (`+build`) and
    other suffixes are dropped. A PEP 440 epoch other than `0!` is not
    modelled and returns None (indeterminate) rather than a wrong order (SC-12).
    Good enough for ordering comparisons here, not a full semver/PEP 440 parse.
    """
    text = version.strip()
    epoch = re.match(r"^(\d+)!", text)
    if epoch:
        if int(epoch.group(1)) != 0:
            return None
        text = text[epoch.end():]
    # Go modules and Composer tags carry a leading `v` (`v1.2.3`).
    m = re.match(r"^v?(\d+(?:\.\d+)*)", text)
    if not m:
        return None
    parts = tuple(int(p) for p in m.group(1).split("."))
    return (*parts, -1) if _PRERELEASE_RE.match(text[m.end():]) else parts


def _cmp(a: tuple[int, ...], b: tuple[int, ...]) -> int:
    la, lb = len(a), len(b)
    n = max(la, lb)
    a = a + (0,) * (n - la)
    b = b + (0,) * (n - lb)
    return (a > b) - (a < b)


_OP_RE = re.compile(r"^\s*(>=|<=|==|!=|~=|\^|~|>|<)\s*(\d[\w.\-+]*)")


def is_exact_version(spec: str) -> bool:
    """True if `spec` names one specific version (a lockfile pin), not a range."""
    spec = spec.strip()
    if not spec or spec == "*":
        return False
    if "," in spec or "||" in spec or " " in spec.strip():
        return False
    if spec[0].isdigit() or (spec[0] == "v" and len(spec) > 1 and spec[1].isdigit()):
        # Wildcard/prefix versions are ranges, not exact pins.
        return bool(re.fullmatch(r"v?\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?", spec))
    m = _OP_RE.match(spec)
    return bool(m and m.group(1) == "==" and bool(re.fullmatch(r"\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.-]+)?", m.group(2))))


def _single_constraint_satisfied(op: str, bound: tuple[int, ...], version: tuple[int, ...]) -> bool:
    c = _cmp(version, bound)
    if op in (">=",):
        return c >= 0
    if op == "<=":
        return c <= 0
    if op in ("==",):
        return c == 0
    if op == "!=":
        return c != 0
    if op == ">":
        return c > 0
    if op == "<":
        return c < 0
    if op == "~=":
        # PEP 440 compatible release: ~=1.4.2 means >=1.4.2, ==1.4.*
        return c >= 0 and version[: len(bound) - 1] == bound[: len(bound) - 1]
    if op == "^":
        # npm caret: ^1.2.3 means >=1.2.3, <2.0.0 (or <0.x+1.0 for 0.x.y)
        if c < 0:
            return False
        major = bound[0] if bound else 0
        if major > 0:
            return version[0] == major
        minor = bound[1] if len(bound) > 1 else 0
        if minor > 0:
            return version[0] == 0 and (len(version) < 2 or version[1] == minor)
        return version[0] == 0 and (len(version) < 2 or version[1] == 0)
    if op == "~":
        # npm tilde: ~1.2.3 means >=1.2.3, <1.3.0
        if c < 0:
            return False
        return version[0] == (bound[0] if bound else 0) and (
            len(bound) < 2 or (len(version) > 1 and version[1] == bound[1])
        )
    return False


_NEG_INF = (-1,)
_POS_INF = (10**9,)

_HYPHEN_RANGE_RE = re.compile(r"^\s*(\d[\w.\-+]*)\s+-\s+(\d[\w.\-+]*)\s*$")
_OP_SPACE_RE = re.compile(r"(>=|<=|==|!=|~=|\^|~|>|<)\s+")


def _split_constraints(spec: str) -> list[str]:
    """Split a spec into AND-ed constraints.

    Handles pip commas, npm `&&`, npm space-joined ranges (`>=1.0.0 <2.0.0`)
    and the npm hyphen range (`1.2.3 - 2.3.4`, rewritten to `>=lo`, `<=hi`).
    """
    m = _HYPHEN_RANGE_RE.match(spec)
    if m:
        return [f">={m.group(1)}", f"<={m.group(2)}"]
    # `>= 1.0` is one constraint: glue an operator to the version that follows
    # it before splitting on whitespace.
    spec = _OP_SPACE_RE.sub(r"\1", spec)
    return [c.strip() for c in re.split(r",|\s+&&\s+|\s+", spec) if c.strip()]


def parse_spec_bounds(spec: str) -> tuple[tuple[int, ...], tuple[int, ...]] | None:
    """Parse a range spec into a half-open interval [lower, upper).

    Unbounded sides use _NEG_INF/_POS_INF sentinels. Returns None if any
    constraint in the spec doesn't parse (indeterminate) -- e.g. npm's `||`
    OR-combinator, which this module doesn't attempt to solve.
    """
    if "||" in spec:
        return None
    constraints = _split_constraints(spec)
    if not constraints:
        return None

    lo, hi = _NEG_INF, _POS_INF

    for constraint in constraints:
        m = _OP_RE.match(constraint)
        if not m:
            bound = parse_version_tuple(constraint)
            if bound is None:
                return None
            lo, hi = bound, _next_tuple(bound)
            continue
        op, bound_str = m.group(1), m.group(2)
        bound = parse_version_tuple(bound_str)
        if bound is None:
            return None
        if op == ">=":
            lo = max(lo, bound)
        elif op == ">":
            # A strict lower bound advances the precision by one component:
            # >1.2 includes 1.2.1, whereas bumping the last component to
            # (1, 3) incorrectly excludes the entire 1.2 series.
            lo = max(lo, (*bound, 1))
        elif op == "<=":
            # <=1.2 includes patch releases such as 1.2.5. Use the next
            # value at the specified precision as the half-open upper bound.
            # Appending a component (1.2 -> 1.2.1) incorrectly excludes
            # patch releases in the 1.2 series.
            hi = min(hi, _next_tuple(bound))
        elif op == "<":
            hi = min(hi, bound)
        elif op == "==":
            lo, hi = bound, _next_tuple(bound)
        elif op == "~=":
            lo = max(lo, bound)
            hi = min(hi, _next_tuple(bound[:-1]) if len(bound) > 1 else _next_tuple(bound))
        elif op == "^":
            lo = max(lo, bound)
            major = bound[0] if bound else 0
            if major > 0:
                hi = min(hi, (major + 1,))
            else:
                minor = bound[1] if len(bound) > 1 else 0
                hi = min(hi, (0, minor + 1)) if minor > 0 else min(hi, (0, 1))
        elif op == "~":
            lo = max(lo, bound)
            # ~1.2.3 is <1.3.0; ~1 is <2.0.0.
            hi = min(hi, (bound[0], bound[1] + 1) if len(bound) > 1 else (bound[0] + 1,))
        elif op == "!=":
            # A single excluded version cannot narrow a half-open interval;
            # ignoring it over-approximates, so overlap can only stay True.
            continue
        else:
            return None
    return lo, hi


def _next_tuple(t: tuple[int, ...]) -> tuple[int, ...]:
    """Smallest tuple strictly greater than t under _cmp (bump the last component)."""
    if not t:
        return (1,)
    return (*t[:-1], t[-1] + 1)


def intervals_overlap(
    a_lo: tuple[int, ...], a_hi: tuple[int, ...], b_lo: tuple[int, ...], b_hi: tuple[int, ...]
) -> bool:
    """Do [a_lo, a_hi) and [b_lo, b_hi) overlap?"""
    return _cmp(a_lo, b_hi) < 0 and _cmp(b_lo, a_hi) < 0


def osv_affected_intervals(affected: list[dict]) -> list[tuple[tuple[int, ...], tuple[int, ...]]] | None:
    """Extract [introduced, fixed) vulnerable-version intervals from an OSV
    vuln's `affected[].ranges[].events` -- the general form is a sequence of
    introduced/fixed(-or-last_affected) event pairs (rarely more than one
    pair, but the schema allows several disjoint vulnerable windows).
    Returns None if any event's version doesn't parse (indeterminate)."""
    intervals: list[tuple[tuple[int, ...], tuple[int, ...]]] = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            lo: tuple[int, ...] | None = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    raw = event["introduced"]
                    lo = _NEG_INF if raw == "0" else parse_version_tuple(raw)
                    if lo is None:
                        return None
                elif "fixed" in event or "last_affected" in event:
                    if lo is None:
                        lo = _NEG_INF
                    if "fixed" in event:
                        hi = parse_version_tuple(event["fixed"])
                    else:
                        bound = parse_version_tuple(event["last_affected"])
                        hi = _next_tuple(bound) if bound is not None else None
                    if hi is None:
                        return None
                    intervals.append((lo, hi))
                    lo = None
            if lo is not None:
                intervals.append((lo, _POS_INF))
    return intervals or None


def spec_overlaps_vulnerable_intervals(spec: str, affected: list[dict]) -> bool | None:
    """Could `spec` (a manifest-only range, not an exact pin) select a
    version inside any of `affected`'s vulnerable ranges?

    Returns None when either side can't be parsed confidently -- callers
    should treat that as "can't rule it out" (keep the finding, flagged
    indeterminate) rather than a hard False, so an unparseable range never
    silently drops a real vulnerability.
    """
    spec_bounds = parse_spec_bounds(spec)
    if spec_bounds is None:
        return None
    intervals = osv_affected_intervals(affected)
    if intervals is None:
        return None
    spec_lo, spec_hi = spec_bounds
    return any(intervals_overlap(spec_lo, spec_hi, lo, hi) for lo, hi in intervals)


def nearest_fixed_version(current: str, affected: list[dict]) -> str | None:
    """Smallest ``fixed`` version in ``affected`` worth upgrading to.

    Scans the OSV ``affected[].ranges[].events[].fixed`` entries and returns
    the lowest fixed version that is strictly greater than ``current`` (an
    exact pin). If ``current`` isn't an exact/parseable version, returns the
    lowest fixed version available -- still a useful remediation target even
    when the installed version is only known as a range. Returns None when no
    ``fixed`` event exists (e.g. the advisory only records ``last_affected``,
    meaning no fix has shipped) or none parse.
    """
    current_t = parse_version_tuple(current) if is_exact_version(current) else None

    fixed_versions: list[tuple[tuple[int, ...], str]] = []
    for entry in affected:
        for rng in entry.get("ranges", []):
            if rng.get("type") not in ("ECOSYSTEM", "SEMVER"):
                continue
            for event in rng.get("events", []):
                raw = event.get("fixed")
                if not raw:
                    continue
                parsed = parse_version_tuple(raw)
                if parsed is not None:
                    fixed_versions.append((parsed, raw))

    if not fixed_versions:
        return None
    fixed_versions.sort(key=lambda p: p[0])

    if current_t is not None:
        for parsed, raw in fixed_versions:
            if _cmp(parsed, current_t) > 0:
                return raw
        return None  # already at/above every fixed version
    return fixed_versions[0][1]


def range_could_include(spec: str, version: str) -> bool | None:
    """Does the range `spec` (pip or npm syntax) plausibly include `version`?

    Returns None (indeterminate) if `spec` doesn't parse as a supported
    constraint form -- callers should treat that conservatively (assume it
    might match) rather than as a hard False.
    """
    version_t = parse_version_tuple(version)
    if version_t is None:
        return None

    constraints = _split_constraints(spec)
    if not constraints:
        return None

    for constraint in constraints:
        m = _OP_RE.match(constraint)
        if not m:
            # Bare version with no operator ("1.2.3") means exact-equals.
            bound = parse_version_tuple(constraint)
            if bound is None:
                return None
            if _cmp(version_t, bound) != 0:
                return False
            continue
        op, bound_str = m.group(1), m.group(2)
        bound = parse_version_tuple(bound_str)
        if bound is None:
            return None
        if not _single_constraint_satisfied(op, bound, version_t):
            return False
    return True

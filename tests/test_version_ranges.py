"""Unit tests for rowan.core.version_ranges (GitHub issue #80)."""

from __future__ import annotations

from rowan.core.version_ranges import (
    is_exact_version,
    nearest_fixed_version,
    osv_affected_intervals,
    parse_spec_bounds,
    parse_version_tuple,
    range_could_include,
    spec_overlaps_vulnerable_intervals,
)


def _affected(*fixed_versions: str) -> list[dict]:
    events = [{"introduced": "0"}] + [{"fixed": v} for v in fixed_versions]
    return [{"ranges": [{"type": "ECOSYSTEM", "events": events}]}]


class TestNearestFixedVersion:
    def test_returns_lowest_fix_above_current_exact(self):
        assert nearest_fixed_version("1.2.0", _affected("1.5.0", "2.0.0")) == "1.5.0"

    def test_skips_fixes_at_or_below_current(self):
        # Already past the 1.5.0 fix -> next relevant fix is 2.0.0.
        assert nearest_fixed_version("1.6.0", _affected("1.5.0", "2.0.0")) == "2.0.0"

    def test_none_when_current_at_or_above_all_fixes(self):
        assert nearest_fixed_version("2.0.0", _affected("1.5.0", "2.0.0")) is None

    def test_non_exact_current_returns_lowest_fix(self):
        assert nearest_fixed_version("^1.0.0", _affected("2.0.0", "1.5.0")) == "1.5.0"

    def test_none_when_no_fixed_event(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"last_affected": "1.9.0"},
        ]}]}]
        assert nearest_fixed_version("1.0.0", affected) is None

    def test_none_on_empty_affected(self):
        assert nearest_fixed_version("1.0.0", []) is None


class TestIsExactVersion:
    def test_bare_version_is_exact(self):
        assert is_exact_version("1.2.3") is True

    def test_equals_operator_is_exact(self):
        assert is_exact_version("==1.2.3") is True

    def test_wildcard_is_not_exact(self):
        assert is_exact_version("*") is False

    def test_gte_is_not_exact(self):
        assert is_exact_version(">=1.2.3") is False

    def test_caret_is_not_exact(self):
        assert is_exact_version("^1.2.3") is False

    def test_comma_combined_is_not_exact(self):
        assert is_exact_version(">=1.0,<2.0") is False

    def test_empty_is_not_exact(self):
        assert is_exact_version("") is False


class TestRangeCouldInclude:
    def test_gte_includes_higher_version(self):
        assert range_could_include(">=1.0.0", "2.0.0") is True

    def test_gte_excludes_lower_version(self):
        assert range_could_include(">=2.0.0", "1.0.0") is False

    def test_combined_range_includes_middle_version(self):
        assert range_could_include(">=1.0.0,<2.0.0", "1.5.0") is True

    def test_combined_range_excludes_boundary_version(self):
        assert range_could_include(">=1.0.0,<2.0.0", "2.0.0") is False

    def test_caret_range(self):
        assert range_could_include("^1.2.0", "1.9.9") is True
        assert range_could_include("^1.2.0", "2.0.0") is False

    def test_tilde_range(self):
        assert range_could_include("~1.2.0", "1.2.9") is True
        assert range_could_include("~1.2.0", "1.3.0") is False


class TestOsvAffectedIntervals:
    def test_single_introduced_fixed_pair(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.5.0"},
        ]}]}]
        intervals = osv_affected_intervals(affected)
        assert intervals is not None
        assert len(intervals) == 1

    def test_unbounded_upper_when_no_fixed_event(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "1.0.0"}]}]}]
        intervals = osv_affected_intervals(affected)
        assert intervals is not None
        assert len(intervals) == 1

    def test_git_range_type_ignored(self):
        affected = [{"ranges": [{"type": "GIT", "events": [{"introduced": "abcd"}]}]}]
        assert osv_affected_intervals(affected) is None


class TestSpecOverlapsVulnerableIntervals:
    def test_overlapping_range_returns_true(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.5.0"},
        ]}]}]
        assert spec_overlaps_vulnerable_intervals(">=1.0.0,<2.0.0", affected) is True

    def test_non_overlapping_range_returns_false(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.5.0"},
        ]}]}]
        assert spec_overlaps_vulnerable_intervals(">=2.0.0", affected) is False

    def test_or_combined_spec_is_indeterminate(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.5.0"},
        ]}]}]
        assert spec_overlaps_vulnerable_intervals("^1.0.0 || ^2.0.0", affected) is None

    def test_inclusive_partial_upper_bound_includes_patch_releases(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "0"}, {"fixed": "1.3.0"},
        ]}]}]
        assert spec_overlaps_vulnerable_intervals("<=1.2", affected) is True

    def test_inclusive_partial_upper_bound_excludes_next_series(self):
        affected = [{"ranges": [{"type": "ECOSYSTEM", "events": [
            {"introduced": "1.3.0"}, {"fixed": "2.0.0"},
        ]}]}]
        assert spec_overlaps_vulnerable_intervals("<=1.2", affected) is False


class TestNpmSpaceAndHyphenRanges:
    # BACKLOG SC-06

    def test_space_joined_and_keeps_upper_bound(self):
        assert parse_spec_bounds(">=1.0.0 <2.0.0") == ((1, 0, 0), (2, 0, 0))

    def test_hyphen_range_spans_both_endpoints(self):
        assert parse_spec_bounds("1.2.3 - 2.3.4") == ((1, 2, 3), (2, 3, 5))

    def test_range_could_include_space_joined(self):
        assert range_could_include(">=1.0.0 <2.0.0", "2.5.0") is False
        assert range_could_include(">=1.0.0 <2.0.0", "1.5.0") is True

    def test_operator_space_version_is_one_constraint(self):
        assert parse_spec_bounds(">= 1.0") == ((1, 0), (10**9,))
        assert parse_spec_bounds(">= 1.0.0 < 2.0.0") == ((1, 0, 0), (2, 0, 0))

    def test_range_could_include_hyphen(self):
        assert range_could_include("1.2.3 - 2.3.4", "2.0.0") is True
        assert range_could_include("1.2.3 - 2.3.4", "2.4.0") is False


class TestVPrefixedVersions:
    # BACKLOG SC-07

    def test_v_prefix_is_exact(self):
        assert is_exact_version("v1.2.3") is True
        assert parse_version_tuple("v1.2.3") == (1, 2, 3)

    def test_nearest_fix_not_older_than_installed(self):
        assert nearest_fixed_version("v1.2.3", _affected("1.0.5")) is None
        assert nearest_fixed_version("v1.2.3", _affected("1.0.5", "1.3.0")) == "1.3.0"

    def test_bare_v_is_not_a_version(self):
        assert is_exact_version("v") is False
        assert parse_version_tuple("v") is None


def test_epoch_prerelease_and_neq():
    """SC-12."""
    from rowan.core.version_ranges import (
        _cmp,
        parse_spec_bounds,
        parse_version_tuple,
        range_could_include,
        spec_overlaps_vulnerable_intervals,
    )

    # Epochs: 0! is the default epoch; a non-zero epoch is not modelled, so it
    # is indeterminate rather than silently parsed as its epoch number.
    assert parse_version_tuple("0!2.0") == (2, 0)
    assert parse_version_tuple("1!2.0") is None

    # Pre-releases sort below their release; build metadata does not.
    for pre, rel in (("2.0.0rc1", "2.0.0"), ("1.2.3-beta.1", "1.2.3"), ("1.0a1", "1.0"), ("v1.2.3-0.2021", "v1.2.3")):
        assert _cmp(parse_version_tuple(pre), parse_version_tuple(rel)) < 0, pre
        assert _cmp(parse_version_tuple(pre), parse_version_tuple("0.9")) > 0, pre
    assert parse_version_tuple("1.2.3+build.5") == (1, 2, 3)

    # != excludes one version and no longer makes a spec indeterminate.
    assert range_could_include("!=1.2.3", "1.2.3") is False
    assert range_could_include("!=1.2.3", "1.2.4") is True
    assert parse_spec_bounds(">=1.0,!=1.2.3") is not None
    fixed_in_1_1 = [{"ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.1"}]}]}]
    assert spec_overlaps_vulnerable_intervals(">=1.5,!=1.7", fixed_in_1_1) is False

    # npm ~1 means >=1.0.0 <2.0.0.
    assert parse_spec_bounds("~1") == ((1,), (2,))

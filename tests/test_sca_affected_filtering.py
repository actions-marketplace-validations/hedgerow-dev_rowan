"""SC-09: a multi-package OSV advisory is scoped to the queried package."""

from rowan.core.version_ranges import nearest_fixed_version, spec_overlaps_vulnerable_intervals
from rowan.passes.sca import _affected_for

_ADVISORY = [
    {"package": {"name": "example.com/foo", "ecosystem": "Go"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"}, {"fixed": "1.4.0"}]}]},
    {"package": {"name": "example.com/foo/v2", "ecosystem": "Go"},
     "ranges": [{"type": "SEMVER", "events": [{"introduced": "2.0.0"}, {"fixed": "2.1.0"}]}]},
]


def test_multi_package_advisory_scoped():
    affected = _affected_for({"name": "example.com/foo", "ecosystem": "Go"}, _ADVISORY)
    assert spec_overlaps_vulnerable_intervals(">=1.5.0", affected) is False
    assert nearest_fixed_version("1.3.0", affected) == "1.4.0"
    assert nearest_fixed_version("1.5.0", affected) != "2.1.0"


def test_pypi_names_normalise_and_unknown_package_falls_back():
    entry = {"package": {"name": "Zope.Interface", "ecosystem": "PyPI"}, "ranges": []}
    assert _affected_for({"name": "zope-interface", "ecosystem": "PyPI"}, [entry]) == [entry]
    bare = [{"ranges": []}]  # no package field: keep the old behaviour
    assert _affected_for({"name": "x", "ecosystem": "npm"}, bare) == bare

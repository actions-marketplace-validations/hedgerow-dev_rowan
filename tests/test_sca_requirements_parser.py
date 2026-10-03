"""Regression tests for `SCAPass._parse_requirements_txt` (BACKLOG SC-01, SC-02, SC-03)."""

from __future__ import annotations

from rowan.passes.sca import SCAPass


def _parse(tmp_path, content: str):
    p = tmp_path / "requirements.txt"
    p.write_text(content, encoding="utf-8")
    return SCAPass()._parse_requirements_txt(p)


def _by_name(packages):
    return {p["name"]: p["version"] for p in packages}


def test_ranged_requirements_kept(tmp_path):
    # SC-01: only the `==` pin survived; the three ranged deps vanished.
    got = _by_name(_parse(tmp_path, "requests>=2.25.0\nflask~=2.0\nurllib3<1.26\ndjango==3.2.0\n"))
    assert got == {
        "requests": ">=2.25.0",
        "flask": "~=2.0",
        "urllib3": "<1.26",
        "django": "3.2.0",
    }


def test_url_requirement_does_not_crash_or_duplicate(tmp_path):
    # SC-02: a first non-matching line raised UnboundLocalError; a later one
    # re-appended the previous package under stale locals.
    got = _parse(
        tmp_path, "mypkg @ https://example.invalid/x.whl\nrequests==2.0\nother @ git+https://x/y\n"
    )
    assert [p["name"] for p in got] == ["requests"]


def test_markers_and_hashes_stripped(tmp_path):
    # SC-03: markers and hashes were folded into the version string.
    got = _by_name(
        _parse(
            tmp_path,
            "requests==2.0 ; python_version<'3.8'\n"
            "numpy==1.0 --hash=sha256:abc\n"
            "flask>=2.0; sys_platform == 'linux'\n"
            "click[extra]==8.1  # pinned\n",
        )
    )
    assert got == {"requests": "2.0", "numpy": "1.0", "flask": ">=2.0", "click": "8.1"}


def test_bare_name_is_unpinned(tmp_path):
    got = _by_name(_parse(tmp_path, "requests\n"))
    assert got == {"requests": "*"}


def test_osv_query_strips_v_prefix():
    # SC-07: go.mod `v1.2.3` is an exact pin, sent to OSV as `1.2.3`.
    from unittest.mock import MagicMock, patch

    sca = SCAPass()
    resp = MagicMock(status_code=200)
    resp.json.return_value = {"results": [{"vulns": []}]}
    resp.raise_for_status.return_value = None
    with patch("rowan.passes.sca.httpx.post", return_value=resp) as post:
        sca._query_osv_batch(
            [{"name": "golang.org/x/net", "version": "v0.30.0", "ecosystem": "Go"}]
        )
    body = post.call_args.kwargs["json"]
    assert body["queries"][0]["version"] == "0.30.0"

"""Symlink-escape regression tests for every file-discovery walk (issue #226).

A scanned repository is untrusted input. rglob("*") does not recurse into a
symlinked *directory*, but it does yield a symlink to a *file*, and
Path.is_file() follows it. Without an explicit containment check, a hostile
repo can make any of these walks return a path outside the scan root, whose
content then gets read into dependency extraction, MCP config parsing, taint
analysis, or (via rowan.agents.workflow, covered separately in
test_path_safety.py) LLM finding context.

Each test below builds the same fixture: a scan root containing a symlink
that resolves to a file outside it, and asserts the discovery function never
returns that escaped path.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from rowan.core.paths import is_within_root


def _make_escape_fixture(tmp_path: Path, link_name: str) -> tuple[Path, Path]:
    """Create tmp_path/link_name -> a file outside tmp_path. Returns (link, outside_target)."""
    outside_dir = Path(tempfile.mkdtemp())
    outside_file = outside_dir / "secret.txt"
    outside_file.write_text("PROD_DB_PASSWORD=hunter2\n")
    link = tmp_path / link_name
    link.symlink_to(outside_file)
    return link, outside_file


class TestIsWithinRoot:
    def test_path_under_root_is_within(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n")
        assert is_within_root(tmp_path / "a.py", tmp_path)

    def test_root_itself_is_within(self, tmp_path):
        assert is_within_root(tmp_path, tmp_path)

    def test_path_outside_root_is_not_within(self, tmp_path):
        outside = Path(tempfile.mkdtemp())
        assert not is_within_root(outside, tmp_path)

    def test_symlink_escape_is_not_within(self, tmp_path):
        link, _ = _make_escape_fixture(tmp_path, "evil.py")
        assert not is_within_root(link, tmp_path)


class TestSCAPassSymlinkEscape:
    def test_find_dep_files_skips_escaped_symlink(self, tmp_path):
        from rowan.passes.sca import SCAPass

        link, outside = _make_escape_fixture(tmp_path, "requirements.txt")
        files = SCAPass()._find_dep_files(tmp_path)
        assert outside not in [f.resolve() for f in files]
        assert link not in files

    def test_collect_python_files_skips_escaped_symlink(self, tmp_path):
        from rowan.passes.sca import SCAPass

        link, outside = _make_escape_fixture(tmp_path, "innocuous.py")
        files = SCAPass._collect_python_files(tmp_path)
        assert outside not in [f.resolve() for f in files]
        assert link not in files


class TestMCPConfigSymlinkEscape:
    def test_find_mcp_config_files_skips_escaped_symlink(self, tmp_path):
        from rowan.core.mcp_config import find_mcp_config_files

        link, outside = _make_escape_fixture(tmp_path, "mcp.json")
        files = find_mcp_config_files(tmp_path)
        assert outside not in [f.resolve() for f in files]
        assert link not in files


class TestCrossFileSymlinkEscape:
    def test_collect_python_files_skips_escaped_symlink(self, tmp_path):
        from rowan.passes.cross_file import _collect_python_files

        link, outside = _make_escape_fixture(tmp_path, "innocuous.py")
        files = _collect_python_files(tmp_path)
        assert outside not in [f.resolve() for f in files]
        assert link not in files


class TestSharedDiscoverySymlinkEscape:
    def test_shared_filter_skips_escaped_symlink(self, tmp_path):
        # AuthzPass and every other AST pass discover through this filter
        # since CN-01; the per-pass helper it replaced had the same test.
        from rowan.passes.sources import filter_python_paths

        link, outside = _make_escape_fixture(tmp_path, "innocuous.py")
        files = list(filter_python_paths(tmp_path, tmp_path.rglob("*.py"), [], skip_tests=False))
        assert outside not in [f.resolve() for f in files]
        assert link not in files


class TestJSCrossFileSymlinkEscape:
    def test_collect_js_files_skips_escaped_symlink(self, tmp_path):
        from rowan.passes.js_cross_file import _collect_js_files

        link, outside = _make_escape_fixture(tmp_path, "innocuous.js")
        files = _collect_js_files(tmp_path)
        assert outside not in [f.resolve() for f in files]
        assert link not in files


class TestProfilesSymlinkEscape:
    def test_auto_detect_profile_does_not_read_escaped_symlink(self, tmp_path):
        from rowan.core.profiles import auto_detect_profile

        _, outside = _make_escape_fixture(tmp_path, "innocuous.py")
        outside.write_text("from flask import Flask\napp = Flask(__name__)\n")
        # If the symlink were followed, the Flask import would flip this to "server".
        assert auto_detect_profile(tmp_path) == "library"

"""Regression tests: `.json` is now a recognized language/extension in both
file-discovery layers (`file_scan.py`'s LANGUAGE_EXTENSIONS for the legacy
--legacy-neuroscan path, `opengrep_adapter.py`'s _LANG_EXTENSIONS/
_LANG_INCLUDE_GLOBS for the default pipeline). Before this, JSON files were
invisible to the regex engine entirely regardless of any rule's declared
`languages:` -- there was no extension mapping to discover them by at all.

No NeuroScan rule currently declares `languages: [json]` (this just makes
JSON files discoverable for when one does, and is what the standalone
MCP-config scanner's own file discovery does NOT depend on -- see
test_mcp_config_scan.py, which uses its own filename-based rglob), so these
are unit tests against the discovery layer directly rather than an
end-to-end rule-firing test.
"""

from __future__ import annotations

from rowan.passes.file_scan import LANGUAGE_EXTENSIONS, FileScanPass
from rowan.taint.opengrep_adapter import OpengrepAdapter


def test_file_scan_language_extensions_includes_json():
    assert ".json" in LANGUAGE_EXTENSIONS["json"]


def test_file_matches_languages_recognizes_json_file():
    assert FileScanPass._file_matches_languages("mcp.json", ["json"])
    assert not FileScanPass._file_matches_languages("mcp.json", ["yaml"])


def test_opengrep_adapter_lang_extensions_includes_json():
    assert ".json" in OpengrepAdapter._LANG_EXTENSIONS["json"]


def test_opengrep_adapter_include_globs_includes_json():
    assert "*.json" in OpengrepAdapter._LANG_INCLUDE_GLOBS["json"]

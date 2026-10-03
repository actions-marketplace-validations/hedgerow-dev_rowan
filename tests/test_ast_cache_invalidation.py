"""Regression coverage for AST cache reuse after a path is rewritten."""

from rowan.analysis.source_tracer import trace_source


def test_trace_source_cache_tracks_file_rewrites(tmp_path):
    source = tmp_path / "handler.py"
    source.write_text('value = "fixed"\nuse(value)\n')
    first = trace_source(str(source), "value", 2)

    # Keep the same path, matching tempfile path reuse that previously returned
    # another test's cached AST.
    source.write_text('value = input()\nuse(value)\n')
    second = trace_source(str(source), "value", 2)

    assert first != second
    assert second.label == "cli_input"

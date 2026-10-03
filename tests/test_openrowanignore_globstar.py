"""TE-18: gitignore-style `**` and trailing-slash excludes."""

from pathlib import Path

from rowan.config import ScanConfig
from rowan.passes.file_scan import FileScanPass, _matches_pattern


def test_globstar_patterns_match():
    assert _matches_pattern("src/a.py", "src/**/*.py")
    assert _matches_pattern("src/pkg/a.py", "src/**/*.py")
    assert _matches_pattern("src/p/q/a.py", "src/**/*.py")
    assert _matches_pattern("a/b/gen.py", "**/gen.py")
    assert _matches_pattern("gen.py", "**/gen.py")


def test_single_star_stays_within_one_directory():
    assert not _matches_pattern("src/pkg/a.py", "src/*.py")
    assert _matches_pattern("src/a.py", "src/*.py")


def test_config_excludes_accept_trailing_slash_and_paths(tmp_path: Path):
    (tmp_path / "app").mkdir()
    (tmp_path / "legacy").mkdir()
    app, old, kept = tmp_path / "app" / "a.py", tmp_path / "legacy" / "old.py", tmp_path / "b.py"
    for f in (app, old, kept):
        f.write_text("x = 1\n", encoding="utf-8")
    config = ScanConfig(target=tmp_path, extra_excludes=["app/", "legacy/old.py"])
    skip = FileScanPass([])._should_skip
    assert skip(app, config, tmp_path)
    assert skip(old, config, tmp_path)
    assert not skip(kept, config, tmp_path)


def test_character_classes_still_work_in_path_patterns():
    assert _matches_pattern("gen/a1.py", "gen/[ab]*.py")
    assert not _matches_pattern("gen/c1.py", "gen/[ab]*.py")
    assert _matches_pattern("gen/c1.py", "gen/[!ab]*.py")


def test_repeated_globstar_does_not_backtrack():
    import time

    path = "/".join(["d"] * 40) + "/nope.py"
    start = time.perf_counter()
    assert not _matches_pattern(path, "**/" * 12 + "x.py")
    assert time.perf_counter() - start < 1
    assert _matches_pattern("a/b/x.py", "**/**/x.py")

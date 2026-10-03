"""Tests for default vendored/minified/oversized file excludes in FileScanPass."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.file_scan import FileScanPass


def _make_context(target: Path, **config_kwargs) -> ScanContext:
    config = ScanConfig(target=target, **config_kwargs)
    return ScanContext(target_path=target, config=config, result=ScanResult())


def _collected_names(target: Path, config: ScanConfig) -> set[str]:
    fs_pass = FileScanPass(rules=[])
    return {f.name for f in fs_pass._collect_files(target, config)}


def test_vendored_dir_is_skipped(tmp_path):
    (tmp_path / "app.py").write_text("import os\nos.system('ls')\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("import os\nos.system('ls')\n")

    ctx = _make_context(tmp_path)
    names = _collected_names(tmp_path, ctx.config)

    assert "app.py" in names
    assert "lib.py" not in names


def test_minified_and_bundle_files_are_skipped(tmp_path):
    (tmp_path / "main.js").write_text("const x = 1;\n")
    (tmp_path / "lib.min.js").write_text("const x=1;\n")
    (tmp_path / "swagger-bundle.js").write_text("const x=1;\n")

    ctx = _make_context(tmp_path)
    names = _collected_names(tmp_path, ctx.config)

    assert "main.js" in names
    assert "lib.min.js" not in names
    assert "swagger-bundle.js" not in names


def test_synthetic_minified_single_long_line_is_skipped(tmp_path):
    (tmp_path / "readable.js").write_text("const x = 1;\nconst y = 2;\n")
    long_line = "var data='" + ("a" * 5000) + "';"
    (tmp_path / "widget.js").write_text(long_line)

    ctx = _make_context(tmp_path)
    names = _collected_names(tmp_path, ctx.config)

    assert "readable.js" in names
    assert "widget.js" not in names


def test_file_over_max_bytes_is_skipped(tmp_path):
    (tmp_path / "small.py").write_text("import os\n")
    big = tmp_path / "big.py"
    big.write_text("# pad\n" + ("x = 1\n" * 400_000))
    assert big.stat().st_size > 2_000_000

    ctx = _make_context(tmp_path)
    names = _collected_names(tmp_path, ctx.config)

    assert "small.py" in names
    assert "big.py" not in names


def test_scan_vendored_true_includes_vendored_file(tmp_path):
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "lib.py").write_text("import os\nos.system('ls')\n")

    ctx = _make_context(tmp_path, scan_vendored=True)
    names = _collected_names(tmp_path, ctx.config)

    assert "lib.py" in names


def test_symlink_escaping_scan_root_is_skipped(tmp_path):
    """A symlink pointing outside the scan root must not be followed (CWE-59/22)."""
    root = tmp_path / "proj"
    root.mkdir()
    (root / "app.py").write_text("import os\n")

    outside = tmp_path / "external_secret.py"  # outside the scan root
    outside.write_text("SECRET = 'do-not-read'\n")

    link = root / "evil.py"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this platform")

    names = _collected_names(root, ScanConfig(target=root))

    assert "app.py" in names
    assert "evil.py" not in names  # escaping symlink skipped


def test_collect_files_traverses_target_once(tmp_path, monkeypatch):
    """Discovery must not perform one recursive walk per recognized suffix."""
    (tmp_path / "app.py").write_text("pass\n")
    (tmp_path / "web.js").write_text("const ok = true;\n")
    (tmp_path / "README.md").write_text("docs\n")

    original_rglob = Path.rglob
    calls: list[str] = []

    def recording_rglob(path: Path, pattern: str):
        calls.append(pattern)
        return original_rglob(path, pattern)

    monkeypatch.setattr(Path, "rglob", recording_rglob)

    names = _collected_names(tmp_path, ScanConfig(target=tmp_path))

    assert names == {"app.py", "web.js", "README.md"}
    assert calls == ["*"]


def test_collect_files_does_not_treat_source_named_directories_as_files(tmp_path):
    (tmp_path / "package.py").mkdir()
    (tmp_path / "Dockerfile").mkdir()
    (tmp_path / "actual.py").write_text("pass\n")

    names = _collected_names(tmp_path, ScanConfig(target=tmp_path))

    assert names == {"actual.py"}


def test_collect_files_preserves_exact_name_and_multipart_suffix_matching(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM scratch\n")
    (tmp_path / "dockerfile").write_text("FROM scratch\n")
    (tmp_path / "AGENTS.md").write_text("instructions\n")
    (tmp_path / "agents.md").write_text("not the exact recognized name\n")
    (tmp_path / "review.prompt.md").write_text("prompt\n")
    (tmp_path / ".cursorrules").write_text("rules\n")

    names = _collected_names(
        tmp_path,
        ScanConfig(target=tmp_path, languages=["dockerfile", "ai_instructions"]),
    )

    assert names == {"Dockerfile", "AGENTS.md", "review.prompt.md", ".cursorrules"}


def test_collect_files_preserves_hidden_file_allowlist(tmp_path):
    (tmp_path / ".secret.py").write_text("SECRET = 'hidden'\n")
    (tmp_path / ".env").write_text("TOKEN=value\n")
    (tmp_path / ".cursorrules").write_text("rules\n")

    names = _collected_names(tmp_path, ScanConfig(target=tmp_path))

    assert ".secret.py" not in names
    assert {".env", ".cursorrules"} <= names


def test_collect_files_language_filter_and_ignore_negation_keep_scope(tmp_path):
    (tmp_path / "app.py").write_text("pass\n")
    (tmp_path / "web.js").write_text("const ok = true;\n")
    vendor = tmp_path / "vendor"
    vendor.mkdir()
    (vendor / "keep.py").write_text("pass\n")
    (vendor / "drop.py").write_text("pass\n")
    (tmp_path / ".rowanignore").write_text(
        "vendor/\n!vendor/keep.py\n",
        encoding="utf-8",
    )

    files = FileScanPass(rules=[])._collect_files(
        tmp_path,
        ScanConfig(target=tmp_path, languages=["python"]),
    )
    relative = {str(path.relative_to(tmp_path)) for path in files}

    assert relative == {"app.py", "vendor/keep.py"}

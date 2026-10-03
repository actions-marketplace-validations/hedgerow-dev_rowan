"""Tests for confinement of files discovered in an untrusted scan target."""

from pathlib import Path

from rowan.core.paths import iter_within_root


def test_iter_within_root_skips_file_symlink_outside_scan_root(tmp_path: Path):
    root = tmp_path / "target"
    root.mkdir()
    inside = root / "inside.py"
    inside.write_text("pass\n", encoding="utf-8")
    secret = tmp_path / "secret.py"
    secret.write_text("secret = 'outside'\n", encoding="utf-8")
    (root / "outside.py").symlink_to(secret)

    assert list(iter_within_root(root, "*.py")) == [inside]


def test_iter_within_root_keeps_internal_file_symlink(tmp_path: Path):
    root = tmp_path / "target"
    root.mkdir()
    source = root / "source.py"
    source.write_text("pass\n", encoding="utf-8")
    alias = root / "alias.py"
    alias.symlink_to(source)

    assert set(iter_within_root(root, "*.py")) == {source, alias}

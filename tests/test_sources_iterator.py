"""One discovery policy for every AST pass (BACKLOG CN-01)."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.sources import iter_python_files, iter_python_sources

_CLEAN = "import os\n\ndef f(x):\n    return os.path.join('a', x)\n"


def _repo(tmp_path: Path) -> Path:
    (tmp_path / "app.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "broken.py").write_text("def (:\n", encoding="utf-8")
    (tmp_path / "latin.py").write_bytes(b"x = '\xe9'\n")
    (tmp_path / "deep.py").write_text("x = " + "-" * 100_000 + "1\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_app.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / ".hidden").mkdir()
    (tmp_path / ".hidden" / "h.py").write_text(_CLEAN, encoding="utf-8")
    (tmp_path / "site-packages").mkdir()
    (tmp_path / "site-packages" / "v.py").write_text(_CLEAN, encoding="utf-8")
    return tmp_path


def _ctx(root: Path, **cfg) -> ScanContext:
    return ScanContext(target_path=root, config=ScanConfig(target=root, **cfg), result=ScanResult())


def test_iterator_yields_only_clean_files_and_records_failures(tmp_path):
    ctx = _ctx(_repo(tmp_path))
    names = sorted(p.name for p, _ in iter_python_sources(ctx, owner="x", skip_tests=True))
    assert names == ["app.py", "latin.py"]
    stats = ctx.source_snapshot.stats()
    assert stats["parse_failures"] == 2, stats
    assert "x" not in ctx.result.degraded_passes


def test_skip_tests_false_keeps_test_files(tmp_path):
    ctx = _ctx(_repo(tmp_path))
    names = sorted(p.name for p in iter_python_files(ctx, skip_tests=False))
    assert names == ["app.py", "broken.py", "deep.py", "latin.py", "test_app.py"]


def test_unexpected_error_degrades_pass_instead_of_aborting(tmp_path, monkeypatch):
    ctx = _ctx(_repo(tmp_path))

    def boom(path):
        raise KeyError(path)

    monkeypatch.setattr(ctx.source_snapshot, "python_ast", boom)
    assert list(iter_python_sources(ctx, owner="x", skip_tests=True)) == []
    assert ctx.result.degraded_passes["x"].startswith("4 file(s)")


def test_ci_mode_ignores_rowanignore(tmp_path):
    root = _repo(tmp_path)
    (root / ".rowanignore").write_text("app.py\n", encoding="utf-8")
    assert "app.py" not in {p.name for p in iter_python_files(_ctx(root), skip_tests=True)}
    assert "app.py" in {
        p.name for p in iter_python_files(_ctx(root, ci_mode=True), skip_tests=True)
    }


_PASS_MODULES = [
    "agent_flow",
    "config_taint",
    "dormant_code",
    "mcp_network_exposure",
    "mcp_sampling_approval",
    "mcp_stored_content",
    "membership_inference",
    "model_extraction",
    "multiagent",
    "pii_egress",
    "serialization_scope",
    "training_approval",
    "training_disclosure",
    "web_security",
    "authz",
    "cross_file",
]


@pytest.mark.parametrize("module", _PASS_MODULES)
def test_pass_modules_do_not_reimplement_discovery(module):
    src = (Path(__file__).parent.parent / "rowan" / "passes" / f"{module}.py").read_text()
    assert "ast.parse(" not in src, f"{module} parses on its own"
    assert not re.search(r"part\.startswith\(\"\.\"\)", src), (
        f"{module} has its own hidden-dir test"
    )
    assert "load_ignore_patterns(" not in src, f"{module} loads ignore patterns on its own"

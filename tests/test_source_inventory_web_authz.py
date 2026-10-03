"""Shared-inventory behavior for Python web and authorization passes."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.authz import AuthzPass
from rowan.passes.base import ScanContext, SourceInventory
from rowan.passes.file_scan import FileScanPass, load_ignore_patterns
from rowan.passes.web_security import WebSecurityPass

PASS_TYPES = (WebSecurityPass, AuthzPass)


def _context(
    root: Path, *, languages: list[str] | None = None
) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(
            target=root,
            languages=languages or [],
            enable_authz=True,
        ),
        result=ScanResult(),
    )


def _signature(result: ScanResult) -> list[tuple[str, str, int]]:
    return sorted(
        (finding.rule_id, finding.file_path, finding.start_line)
        for finding in result.findings
    )


def _write_findings_fixture(root: Path) -> None:
    (root / "views.py").write_text(
        "import hashlib\n\n"
        "def whoami(request):\n"
        "    return request.user.id\n\n"
        "def document_detail(request, pk):\n"
        "    doc = Document.objects.get(id=pk)\n"
        "    return render(doc)\n\n"
        "def derive_password_recovery_code(username, email):\n"
        "    return hashlib.sha256(f'{username}:{email}'.encode()).hexdigest()[:12]\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("pass_type", PASS_TYPES)
def test_inventory_results_match_standalone_discovery(tmp_path, pass_type) -> None:
    _write_findings_fixture(tmp_path)
    standalone = pass_type().run(_context(tmp_path))

    shared_context = _context(tmp_path)
    FileScanPass(rules=[]).run(shared_context)
    reused = pass_type().run(shared_context)

    assert _signature(reused) == _signature(standalone)
    assert reused.files_scanned == standalone.files_scanned == 1


@pytest.mark.parametrize("pass_type", PASS_TYPES)
def test_published_inventory_avoids_repository_walk(
    tmp_path, monkeypatch, pass_type
) -> None:
    (tmp_path / "clean.py").write_text("def clean():\n    return 1\n", encoding="utf-8")
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 1


@pytest.mark.parametrize("pass_type", PASS_TYPES)
def test_empty_inventory_is_authoritative(tmp_path, monkeypatch, pass_type) -> None:
    _write_findings_fixture(tmp_path)
    context = _context(tmp_path)
    context.source_inventory = SourceInventory()

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


@pytest.mark.parametrize("pass_type", PASS_TYPES)
def test_non_python_inventory_scope_is_authoritative(
    tmp_path, monkeypatch, pass_type
) -> None:
    _write_findings_fixture(tmp_path)
    (tmp_path / "inside_scope.js").write_text("const clean = true;\n", encoding="utf-8")
    context = _context(tmp_path, languages=["javascript"])
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


def _write_filter_fixture(root: Path) -> dict[str, Path]:
    paths = {
        "included": root / "included.py",
        "ignored": root / "ignored.py",
        "test_name": root / "test_named.py",
        "tests": root / "tests" / "fixture.py",
        "hidden": root / ".hidden" / "hidden.py",
        "site": root / "site-packages" / "dependency.py",
        "node": root / "node_modules" / "dependency.py",
    }
    for path in paths.values():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"def fn_{path.stem}():\n    return 1\n", encoding="utf-8")
    (root / ".rowanignore").write_text("ignored.py\n", encoding="utf-8")
    return paths


def test_web_security_standalone_filters_are_unchanged(tmp_path) -> None:
    paths = _write_filter_fixture(tmp_path)

    parsed = WebSecurityPass()._parse(tmp_path)

    assert {item.path for item in parsed} == {
        paths["included"],
        paths["node"],
    }


def test_authz_standalone_filters_are_unchanged(tmp_path) -> None:
    paths = _write_filter_fixture(tmp_path)

    files = AuthzPass()._python_files(
        tmp_path, load_ignore_patterns(tmp_path)
    )

    assert set(files) == {
        paths["included"],
        paths["test_name"],
        paths["tests"],
    }

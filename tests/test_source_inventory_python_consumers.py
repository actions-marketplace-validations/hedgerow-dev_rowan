"""Shared-inventory migration tests for additional Python analysis passes."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext, SourceInventory
from rowan.passes.dormant_code import DormantCodePass
from rowan.passes.file_scan import FileScanPass
from rowan.passes.membership_inference import MembershipInferencePass
from rowan.passes.model_extraction import ModelExtractionPass

PASS_TYPES = (ModelExtractionPass, MembershipInferencePass, DormantCodePass)


def _context(root: Path, *, languages: list[str] | None = None) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root, languages=languages or []),
        result=ScanResult(),
    )


def _signature(result: ScanResult) -> list[tuple[str, str, int]]:
    return sorted(
        (finding.rule_id, finding.file_path, finding.start_line)
        for finding in result.findings
    )


def _write_equivalence_fixture(root: Path) -> None:
    (root / "model_api.py").write_text(
        "@app.post('/probabilities')\n"
        "def probabilities():\n"
        "    return jsonify(probabilities=model.predict_proba(request.json['rows']))\n",
        encoding="utf-8",
    )
    (root / "membership_api.py").write_text(
        "@app.get('/loss')\n"
        "def loss():\n"
        "    return jsonify(loss=model.record_loss(request.args['row']))\n",
        encoding="utf-8",
    )
    (root / "plugin_store.py").write_text(
        "def store_plugin(source, enabled):\n"
        "    path = PLUGIN_DIR / 'plugin.py'\n"
        "    path.write_bytes(source)\n"
        "    database.add(Plugin(path=str(path), enabled=enabled))\n\n"
        "def install_plugin(source):\n"
        "    return store_plugin(source, enabled=True)\n",
        encoding="utf-8",
    )
    (root / "plugin_api.py").write_text(
        "def upload_plugin():\n"
        "    data = request.get_json() or {}\n"
        "    source = base64.b64decode(data.get('source'))\n"
        "    install_plugin(source)\n",
        encoding="utf-8",
    )
    (root / "plugin_loader.py").write_text(
        "def load_enabled_plugin(name, path):\n"
        "    spec = importlib.util.spec_from_file_location(name, path)\n"
        "    module = importlib.util.module_from_spec(spec)\n"
        "    spec.loader.exec_module(module)\n",
        encoding="utf-8",
    )


@pytest.mark.parametrize("pass_type", PASS_TYPES)
def test_inventory_results_match_standalone_discovery(tmp_path, pass_type) -> None:
    _write_equivalence_fixture(tmp_path)
    standalone = pass_type().run(_context(tmp_path))

    shared_context = _context(tmp_path)
    FileScanPass(rules=[]).run(shared_context)
    reused = pass_type().run(shared_context)

    assert _signature(reused) == _signature(standalone)
    assert reused.files_scanned == standalone.files_scanned


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
    (tmp_path / "outside_scope.py").write_text(
        "def outside_scope():\n    return model.predict_proba(rows)\n",
        encoding="utf-8",
    )
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
    (tmp_path / "outside_scope.py").write_text(
        "def outside_scope():\n    return model.predict_proba(rows)\n",
        encoding="utf-8",
    )
    (tmp_path / "inside_scope.js").write_text("const clean = true;\n", encoding="utf-8")
    context = _context(tmp_path, languages=["javascript"])
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


def _write_excluded_files(root: Path) -> Path:
    included = root / "included.py"
    included.write_text("def included():\n    return 1\n", encoding="utf-8")
    (root / "ignored.py").write_text("def ignored():\n    return 1\n", encoding="utf-8")
    (root / ".rowanignore").write_text("ignored.py\n", encoding="utf-8")
    for directory in (".hidden", "tests", "site-packages"):
        child = root / directory
        child.mkdir()
        (child / "excluded.py").write_text(
            f"def excluded_{directory.replace('-', '_').replace('.', '_')}():\n    return 1\n",
            encoding="utf-8",
        )
    return included


@pytest.mark.parametrize("pass_type", [ModelExtractionPass, MembershipInferencePass])
def test_standalone_model_pass_exclusions_are_unchanged(tmp_path, pass_type) -> None:
    included = _write_excluded_files(tmp_path)

    # These passes historically exclude hidden paths, site-packages, and
    # .rowanignore entries, but do scan a conventional tests directory.
    paths = pass_type._python_files(_context(tmp_path))

    assert set(paths) == {included, tmp_path / "tests" / "excluded.py"}


def test_standalone_dormant_code_exclusions_are_unchanged(tmp_path) -> None:
    included = _write_excluded_files(tmp_path)

    functions = DormantCodePass()._functions(_context(tmp_path))

    assert {function.path for function in functions} == {included}

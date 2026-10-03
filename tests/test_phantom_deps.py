"""Tests for phantom (undeclared) dependency detection.

A phantom dependency is a third-party package imported in code but declared
in no manifest/lockfile. Detection is precision-first: stdlib, first-party
modules, and imports declared under an aliased distribution name must never
be reported.
"""

from __future__ import annotations

from pathlib import Path

from rowan.core.phantom_deps import (
    PhantomDependency,
    collect_imported_modules,
    collect_local_module_names,
    find_phantom_dependencies,
)
from rowan.passes.sca import SCAPass


def _write(root: Path, name: str, content: str) -> Path:
    p = root / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


class TestCollectImportedModules:
    def test_plain_and_from_imports_contribute_root(self, tmp_path):
        _write(tmp_path, "a.py", "import requests\nfrom flask import Flask\n")
        mods = collect_imported_modules([tmp_path / "a.py"])
        assert "requests" in mods
        assert "flask" in mods

    def test_dotted_import_uses_top_level_root(self, tmp_path):
        _write(tmp_path, "a.py", "import mlflow.pyfunc\nfrom google.protobuf import x\n")
        mods = collect_imported_modules([tmp_path / "a.py"])
        assert "mlflow" in mods
        assert "google" in mods

    def test_relative_imports_skipped(self, tmp_path):
        _write(tmp_path, "a.py", "from . import helpers\nfrom ..pkg import thing\n")
        mods = collect_imported_modules([tmp_path / "a.py"])
        assert mods == set()

    def test_unparseable_file_skipped(self, tmp_path):
        _write(tmp_path, "bad.py", "def f(:\n pass")
        _write(tmp_path, "ok.py", "import requests\n")
        mods = collect_imported_modules([tmp_path / "bad.py", tmp_path / "ok.py"])
        assert "requests" in mods


class TestCollectLocalModuleNames:
    def test_package_dirs_and_file_stems_are_local(self, tmp_path):
        _write(tmp_path, "myapp/__init__.py", "")
        _write(tmp_path, "myapp/util.py", "")
        _write(tmp_path, "script.py", "")
        local = collect_local_module_names(
            tmp_path,
            [tmp_path / "myapp/__init__.py", tmp_path / "myapp/util.py", tmp_path / "script.py"],
        )
        assert "myapp" in local
        assert "util" in local
        assert "script" in local

    def test_authoritative_candidates_do_not_walk_for_extra_packages(
        self, tmp_path, monkeypatch
    ):
        init = _write(tmp_path, "myapp/__init__.py", "")

        def unexpected_walk(*args, **kwargs):
            raise AssertionError("authoritative inventory must not be widened")

        monkeypatch.setattr(
            "rowan.core.phantom_deps.iter_within_root", unexpected_walk
        )
        assert collect_local_module_names(
            tmp_path, [init], authoritative=True
        ) == {"__init__", "myapp"}


class TestFindPhantomDependencies:
    def test_undeclared_third_party_is_phantom(self):
        phantoms = find_phantom_dependencies(
            imported_modules={"requests", "flask"},
            declared_pypi={"flask"},
            local_modules=set(),
        )
        assert phantoms == [PhantomDependency(import_name="requests", distribution="requests")]

    def test_stdlib_never_phantom(self):
        phantoms = find_phantom_dependencies(
            imported_modules={"os", "sys", "json", "asyncio", "pathlib"},
            declared_pypi={"flask"},
            local_modules=set(),
        )
        assert phantoms == []

    def test_first_party_module_never_phantom(self):
        phantoms = find_phantom_dependencies(
            imported_modules={"myapp", "requests"},
            declared_pypi={"requests"},
            local_modules={"myapp"},
        )
        assert phantoms == []

    def test_alias_mapped_distribution_matches_declared(self):
        # Code imports `PIL`/`cv2`/`sklearn`; manifest declares the real
        # distribution names -- none of these are phantom.
        phantoms = find_phantom_dependencies(
            imported_modules={"PIL", "cv2", "sklearn", "yaml"},
            declared_pypi={"pillow", "opencv-python", "scikit-learn", "pyyaml"},
            local_modules=set(),
        )
        assert phantoms == []

    def test_normalization_across_separators(self):
        # scikit_learn (import) vs scikit-learn (declared) must match after
        # normalization even without hitting the alias map.
        phantoms = find_phantom_dependencies(
            imported_modules={"scikit_learn"},
            declared_pypi={"scikit-learn"},
            local_modules=set(),
        )
        assert phantoms == []

    def test_ambiguous_namespace_skipped(self):
        # `google` maps to many distributions -- never guessed.
        phantoms = find_phantom_dependencies(
            imported_modules={"google"},
            declared_pypi={"flask"},
            local_modules=set(),
        )
        assert phantoms == []

    def test_private_root_skipped(self):
        phantoms = find_phantom_dependencies(
            imported_modules={"_pytest", "_distutils_hack"},
            declared_pypi={"flask"},
            local_modules=set(),
        )
        assert phantoms == []

    def test_phantom_reports_best_effort_distribution_name(self):
        phantoms = find_phantom_dependencies(
            imported_modules={"PIL"},
            declared_pypi={"flask"},
            local_modules=set(),
        )
        assert phantoms == [PhantomDependency(import_name="PIL", distribution="pillow")]

    def test_result_is_sorted(self):
        phantoms = find_phantom_dependencies(
            imported_modules={"zeta", "alpha", "mid"},
            declared_pypi={"flask"},
            local_modules=set(),
        )
        assert [p.import_name for p in phantoms] == ["alpha", "mid", "zeta"]


class TestSCAPassPhantomIntegration:
    def _run(self, tmp_path) -> list:
        declared = (
            {pkg["name"] for pkg in SCAPass()._parse_requirements_txt(tmp_path / "requirements.txt")}
            if (tmp_path / "requirements.txt").exists()
            else set()
        )
        return SCAPass()._detect_phantom_dependencies(declared, tmp_path)

    def test_end_to_end_flags_undeclared_import(self, tmp_path):
        _write(tmp_path, "requirements.txt", "flask==2.0.0\n")
        _write(tmp_path, "app.py", "import flask\nimport requests\nrequests.get('x')\n")
        findings = self._run(tmp_path)
        rule_ids = {f.rule_id for f in findings}
        assert "SCA-PHANTOM-001" in rule_ids
        phantom = next(f for f in findings if f.rule_id == "SCA-PHANTOM-001")
        assert phantom.metadata["import_name"] == "requests"
        assert phantom.severity.value == "info"
        assert phantom.engine == "depguard"

    def test_declared_import_not_flagged(self, tmp_path):
        _write(tmp_path, "requirements.txt", "flask==2.0.0\nrequests==2.28.0\n")
        _write(tmp_path, "app.py", "import flask\nimport requests\n")
        findings = self._run(tmp_path)
        assert findings == []

    def test_no_python_baseline_skips_detection(self, tmp_path):
        # No PyPI packages declared -> nothing is "undeclared relative to" it.
        _write(tmp_path, "app.py", "import requests\n")
        findings = SCAPass()._detect_phantom_dependencies(set(), tmp_path)
        assert findings == []

    def test_first_party_package_not_flagged_end_to_end(self, tmp_path):
        _write(tmp_path, "requirements.txt", "flask==2.0.0\n")
        _write(tmp_path, "myapp/__init__.py", "")
        _write(tmp_path, "myapp/main.py", "import flask\nfrom myapp import util\nimport myapp.util\n")
        _write(tmp_path, "myapp/util.py", "x = 1\n")
        findings = self._run(tmp_path)
        assert findings == []

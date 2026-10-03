from __future__ import annotations

from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.dormant_code import DormantCodePass


def _write(root: Path, name: str, source: str) -> None:
    (root / name).write_text(source, encoding="utf-8")


def _scan(root: Path):
    return DormantCodePass().run(
        ScanContext(root, ScanConfig(root), ScanResult())
    ).findings


def _plugin_loader(root: Path) -> None:
    _write(
        root,
        "plugin_loader.py",
        """
import importlib.util

def import_plugin(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

def load_enabled_plugins():
    for name, path in database.enabled_plugins():
        import_plugin(name, path)
""",
    )


def test_uploaded_source_enabled_now_and_imported_later_is_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "plugin_store.py",
        """
def store_plugin(name, source, enabled):
    path = PLUGIN_DIR / f"{name}.py"
    path.write_bytes(source)
    database.add(Plugin(path=str(path), enabled=enabled))

def install_plugin(name, source):
    return store_plugin(name, source, enabled=True)
""",
    )
    _write(
        tmp_path,
        "api.py",
        """
from flask import request
from plugin_store import install_plugin

def upload_plugin():
    data = request.get_json() or {}
    source = base64.b64decode(data.get("source"))
    install_plugin(data.get("name", "extension"), source)
""",
    )
    _plugin_loader(tmp_path)

    findings = _scan(tmp_path)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "LIFECYCLE-UPLOADED-CODE-001"
    assert finding.cwe_ids == [829]
    assert finding.taint_flow is not None
    assert finding.taint_flow.source.file_path.endswith("api.py")
    assert finding.taint_flow.sink.file_path.endswith("plugin_loader.py")


def test_review_gated_plugin_is_not_treated_as_executable(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "plugin_store.py",
        """
def store_plugin(name, source, enabled):
    path = PLUGIN_DIR / f"{name}.py"
    path.write_bytes(source)
    database.add(Plugin(path=str(path), enabled=enabled))

def stage_plugin(name, source):
    return store_plugin(name, source, enabled=False)
""",
    )
    _write(
        tmp_path,
        "api.py",
        """
from flask import request
from plugin_store import stage_plugin

def upload_for_review():
    data = request.get_json() or {}
    stage_plugin(data.get("name", "extension"), data.get("source", "").encode())
""",
    )
    _plugin_loader(tmp_path)

    assert _scan(tmp_path) == []


def test_unrelated_uploaded_document_does_not_pair_with_plugin_loader(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "documents.py",
        """
from flask import request

def upload_document():
    data = request.get_json() or {}
    Path("documents/profile.json").write_text(data.get("profile", ""))
""",
    )
    _plugin_loader(tmp_path)

    assert _scan(tmp_path) == []


def test_request_archive_extracted_and_imported_immediately_is_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "hub.py",
        """
import io
import importlib.util
import zipfile

def import_repository(repo_name, archive_bytes):
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        archive.extractall(REPO_DIR / repo_name)
    source = REPO_DIR / repo_name / "hubconf.py"
    spec = importlib.util.spec_from_file_location(repo_name, source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
""",
    )
    _write(
        tmp_path,
        "api.py",
        """
from flask import request
from hub import import_repository

def upload_model_repository():
    data = request.get_json() or {}
    archive = base64.b64decode(data.get("archive"))
    return import_repository(data.get("name"), archive)
""",
    )
    findings = _scan(tmp_path)
    assert len(findings) == 1
    assert findings[0].rule_id == "IMPORTED-REPO-CODE-001"
    assert findings[0].cwe_ids == [829]
    assert findings[0].taint_flow is not None


def test_data_only_archive_without_code_import_is_not_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "dataset.py",
        """
import io
import zipfile

def import_dataset(archive_bytes):
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        archive.extractall(DATA_DIR)
""",
    )
    _write(
        tmp_path,
        "api.py",
        """
from flask import request
from dataset import import_dataset

def upload_dataset():
    return import_dataset(request.get_data())
""",
    )
    assert _scan(tmp_path) == []


def test_signed_manifest_reader_without_source_execution_is_not_reported(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "hub.py",
        """
import io
import zipfile

def inspect_signed_repository(archive_bytes):
    with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
        manifest = archive.read("manifest.json")
    verify_signature(manifest)
    return json.loads(manifest)
""",
    )
    _write(
        tmp_path,
        "api.py",
        """
from flask import request
from hub import inspect_signed_repository

def upload_model_repository():
    return inspect_signed_repository(request.get_data())
""",
    )
    assert _scan(tmp_path) == []

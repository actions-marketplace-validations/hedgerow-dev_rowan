"""Shared source-inventory publication and first consumer migrations."""

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.agent_flow import AgentFlowPass
from rowan.passes.base import ScanContext, SourceInventory
from rowan.passes.config_taint import ConfigTaintPass
from rowan.passes.file_scan import FileScanPass
from rowan.passes.pii_egress import PiiEgressPass
from rowan.passes.training_approval import TrainingApprovalPass
from rowan.passes.training_disclosure import TrainingDisclosurePass

_INVENTORY_CONSUMERS = (
    PiiEgressPass,
    TrainingDisclosurePass,
    TrainingApprovalPass,
    ConfigTaintPass,
    AgentFlowPass,
)


def _context(root: Path) -> ScanContext:
    return ScanContext(
        target_path=root,
        config=ScanConfig(target=root),
        result=ScanResult(),
    )


def _finding_signature(result: ScanResult) -> list[tuple[str, str, int]]:
    return sorted(
        (finding.rule_id, finding.file_path, finding.start_line)
        for finding in result.findings
    )


def test_file_scan_publishes_filtered_typed_inventory(tmp_path):
    (tmp_path / "app.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "types.pyi").write_text("value: int\n", encoding="utf-8")
    (tmp_path / "notes.md").write_text("notes\n", encoding="utf-8")
    (tmp_path / ".secret.py").write_text("secret = 1\n", encoding="utf-8")

    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    assert isinstance(context.source_inventory, SourceInventory)
    by_name = {entry.path.name: entry for entry in context.source_inventory.files}
    assert set(by_name) == {"app.py", "types.pyi", "notes.md"}
    assert "python" in by_name["app.py"].languages
    assert "python" in by_name["types.pyi"].languages
    assert "markdown" in by_name["notes.md"].languages
    assert context.source_inventory.paths_for("python", suffix=".py") == (
        tmp_path / "app.py",
    )


def test_file_scan_counts_unsupported_source_languages(tmp_path):
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    (tmp_path / "b.swift").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / "c").mkdir()
    (tmp_path / "c" / "d.swift").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / "e.scala").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "x.swift").write_text("val x = 1\n", encoding="utf-8")
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "y.swift").write_text("val x = 1\n", encoding="utf-8")

    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    assert context.metadata["unsupported_languages_seen"] == {"swift": 2, "scala": 1}
    assert context.metadata["languages_seen"] == {"python": 1}


@pytest.mark.parametrize("pass_type", [PiiEgressPass, TrainingDisclosurePass])
def test_python_pass_inventory_matches_standalone_results(tmp_path, pass_type):
    (tmp_path / "pii.py").write_text(
        "def send_profile(user, client):\n"
        "    prompt = f'Email: {user.email}'\n"
        "    return client.chat.completions.create(messages=[{'content': prompt}])\n",
        encoding="utf-8",
    )
    (tmp_path / "training.py").write_text(
        "@app.post('/chat')\n"
        "def chat():\n"
        "    rows = TrainingTranscript.query.all()\n"
        "    return jsonify(answer=' '.join(row.email for row in rows))\n",
        encoding="utf-8",
    )

    standalone = pass_type().run(_context(tmp_path))

    shared_context = _context(tmp_path)
    FileScanPass(rules=[]).run(shared_context)
    reused = pass_type().run(shared_context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert reused.files_scanned == standalone.files_scanned


def _write_second_wave_fixture(root: Path, pass_type) -> None:
    if pass_type is TrainingApprovalPass:
        (root / "models.py").write_text(
            "class Feedback:\n"
            "    \"\"\"User correction awaiting review.\"\"\"\n"
            "    features = Column(Text)\n"
            "    label = Column(String)\n"
            "    status = Column(String)\n",
            encoding="utf-8",
        )
        (root / "worker.py").write_text(
            "def retrain(model):\n"
            "    rows = Feedback.query.all()\n"
            "    trainer.fit(model, rows)\n",
            encoding="utf-8",
        )
    elif pass_type is ConfigTaintPass:
        (root / "writer.py").write_text(
            "def save_config():\n"
            "    data = request.get_json()\n"
            "    runtime_settings.merge_namespace(data.get('namespace'), data)\n",
            encoding="utf-8",
        )
        (root / "reader.py").write_text(
            "def read(path):\n"
            "    strict = runtime_settings.get_bool('security.strict', True)\n"
            "    if strict:\n"
            "        path = sanitize_path(path)\n"
            "    return open(path)\n",
            encoding="utf-8",
        )
    else:
        (root / "agent.py").write_text(
            "def run_agent(rounds):\n"
            "    for _ in range(rounds):\n"
            "        client.chat(messages=[])\n",
            encoding="utf-8",
        )
        (root / "api.py").write_text(
            "@app.post('/ask')\n"
            "def ask():\n"
            "    return run_agent(request.args.get('rounds'))\n",
            encoding="utf-8",
        )


@pytest.mark.parametrize(
    "pass_type", [TrainingApprovalPass, ConfigTaintPass, AgentFlowPass]
)
def test_second_wave_inventory_matches_standalone_results(tmp_path, pass_type):
    _write_second_wave_fixture(tmp_path, pass_type)

    standalone = pass_type().run(_context(tmp_path))
    shared_context = _context(tmp_path)
    FileScanPass(rules=[]).run(shared_context)
    reused = pass_type().run(shared_context)

    assert _finding_signature(reused) == _finding_signature(standalone)
    assert reused.files_scanned == standalone.files_scanned


@pytest.mark.parametrize("pass_type", _INVENTORY_CONSUMERS)
def test_python_pass_reuses_inventory_without_repository_walk(tmp_path, monkeypatch, pass_type):
    source = tmp_path / "clean.py"
    source.write_text("def clean():\n    return 1\n", encoding="utf-8")
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 1


@pytest.mark.parametrize("pass_type", _INVENTORY_CONSUMERS)
def test_empty_published_inventory_does_not_fall_back_to_repository_walk(
    tmp_path, monkeypatch, pass_type
):
    context = _context(tmp_path)
    context.source_inventory = SourceInventory()

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


@pytest.mark.parametrize("pass_type", _INVENTORY_CONSUMERS)
def test_non_python_language_scope_prevents_specialized_python_work(
    tmp_path, monkeypatch, pass_type
):
    (tmp_path / "outside_scope.py").write_text(
        "def unsafe(user, client):\n"
        "    return client.chat.completions.create(messages=[user.email])\n",
        encoding="utf-8",
    )
    (tmp_path / "inside_scope.js").write_text("const value = 1;\n", encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path, languages=["javascript"]),
        result=ScanResult(),
    )
    FileScanPass(rules=[]).run(context)

    def unexpected_walk(self, pattern):
        raise AssertionError(f"unexpected repository walk: {self} {pattern}")

    monkeypatch.setattr(Path, "rglob", unexpected_walk)

    result = pass_type().run(context)
    assert result.files_scanned == 0
    assert result.findings == []


@pytest.mark.parametrize("pass_type", _INVENTORY_CONSUMERS)
def test_inventory_reuse_preserves_pass_specific_hidden_directory_exclusion(
    tmp_path, pass_type
):
    included = tmp_path / "included.py"
    included.write_text("def included():\n    return 1\n", encoding="utf-8")
    hidden = tmp_path / ".fixtures"
    hidden.mkdir()
    (hidden / "excluded.py").write_text(
        "def excluded():\n    return 1\n", encoding="utf-8"
    )
    context = _context(tmp_path)
    FileScanPass(rules=[]).run(context)
    assert context.source_inventory is not None
    assert {source.path.name for source in context.source_inventory.files} == {
        "included.py",
        "excluded.py",
    }

    result = pass_type().run(context)
    assert result.files_scanned == 1


@pytest.mark.parametrize("pass_type", _INVENTORY_CONSUMERS)
def test_standalone_fallback_preserves_hidden_site_package_and_ignore_exclusions(
    tmp_path, pass_type
):
    included = tmp_path / "included.py"
    included.write_text("def included():\n    return 1\n", encoding="utf-8")
    ignored = tmp_path / "ignored.py"
    ignored.write_text("def ignored():\n    return 1\n", encoding="utf-8")
    (tmp_path / ".rowanignore").write_text("ignored.py\n", encoding="utf-8")
    hidden = tmp_path / ".hidden"
    hidden.mkdir()
    (hidden / "hidden.py").write_text("def hidden():\n    return 1\n", encoding="utf-8")
    packages = tmp_path / "site-packages"
    packages.mkdir()
    (packages / "dependency.py").write_text(
        "def dependency():\n    return 1\n", encoding="utf-8"
    )

    result = pass_type().run(_context(tmp_path))

    assert result.files_scanned == 1

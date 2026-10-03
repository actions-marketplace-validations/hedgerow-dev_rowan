"""`--ci` must not trust suppression files committed in the scanned repo
(BACKLOG PL-02): a PR could otherwise silence the gate by adding one."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from rowan import cli

_APP = (
    "import pickle\n"
    "from flask import request\n\n"
    "def load():\n"
    "    return pickle.loads(request.data)\n"
)


def _scan(tmp_path: Path, *args: str):
    result = CliRunner().invoke(
        cli.main, ["scan", str(tmp_path), "--format", "json", "--no-sca", *args]
    )
    data = json.loads(result.output) if result.output.strip().startswith("{") else {}
    return result.exit_code, data


def test_ci_ignores_fingerprint_ignore_file(tmp_path: Path):
    (tmp_path / "app.py").write_text(_APP, encoding="utf-8")
    rules = [
        "NS-DESER-001",
        "TNT-DESER-001",
        "TNT-DESER-006",
        "TNT-PATH-003",
        "TNT-PY-FWK-DESER-001",
        "TNT-SSRF-003",
        "TNT-SUPPLY-001",
    ]
    (tmp_path / ".rowan-ignore.yml").write_text(
        "ignore:\n" + "".join(f"  - rule_id: {r}\n    reason: silence\n" for r in rules),
        encoding="utf-8",
    )
    code, data = _scan(tmp_path)
    assert not data.get("findings"), "sanity: the ignore file suppresses outside CI"
    code, data = _scan(tmp_path, "--ci")
    assert code == 1
    assert data["findings"], "the ignore file must not suppress under --ci"
    assert data["ignore_file_skipped"].endswith(".rowan-ignore.yml")


def test_ci_ignores_rowanignore(tmp_path: Path):
    (tmp_path / "app.py").write_text(_APP, encoding="utf-8")
    (tmp_path / ".rowanignore").write_text("*.py\n", encoding="utf-8")
    code, data = _scan(tmp_path)
    assert not data.get("findings"), "sanity: .rowanignore excludes the file outside CI"
    code, data = _scan(tmp_path, "--ci")
    assert code == 1
    assert data["findings"]

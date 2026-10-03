"""Tests for the MCP evidence server (rowan/mcp_server.py).

collect_evidence is a pure function over ScanPipeline + the JSON reporter, so
it is tested without the optional mcp dependency; the tool registration test
skips when mcp is not installed.
"""

from __future__ import annotations

import importlib.util
import textwrap
from pathlib import Path

import pytest

from rowan.mcp_server import collect_evidence


def _write_vulnerable_app(tmp_path: Path) -> Path:
    target = tmp_path / "app"
    target.mkdir()
    (target / "handler.py").write_text(
        textwrap.dedent(
            """\
            import hashlib
            import pickle
            from flask import Flask, request

            app = Flask(__name__)


            @app.route("/load", methods=["POST"])
            def load():
                return str(pickle.loads(request.data))


            def weak_digest(password: str) -> str:
                return hashlib.md5(password.encode()).hexdigest()
            """
        ),
        encoding="utf-8",
    )
    return target


def test_collect_evidence_payload_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(tmp_path))
    payload = collect_evidence(str(_write_vulnerable_app(tmp_path)))

    assert "error" not in payload
    assert payload["scanner"] == "rowan"
    assert "analysis_capability" in payload
    assert "dataflow_languages" in payload["analysis_capability"]

    findings = payload["findings"]
    assert findings, "pickle.loads(request.data) behind @app.route must produce findings"
    # Tier stamping is TOTAL: a consumer must never see a null tier and have
    # to invent a trust policy for it.
    untiered = [f["rule_id"] for f in findings if not f.get("evidence_tier")]
    assert not untiered, f"findings without evidence_tier: {untiered}"
    # A source-context tier is no longer manufactured from surrounding code.
    # Only the findings with an actual trace receive the taint-flow tier.
    deser = [f for f in findings if f["category"] == "deserialization"]
    assert deser
    assert all(f["evidence_tier"] == ("taint-flow" if f.get("taint_flow") else "pattern-only") for f in deser)
    # md5-for-password is a non-dataflow claim: the matched text is the whole
    # claim, so it must be tiered self-evident, not left null or capped.
    crypto = [f for f in findings if f["category"] == "crypto"]
    assert crypto, "hashlib.md5 on a password must produce a crypto finding"
    assert all(f["evidence_tier"] == "self-evident" for f in crypto)


def test_collect_evidence_missing_target() -> None:
    payload = collect_evidence("/nonexistent/path/for/rowan/mcp/test")
    assert "error" in payload
    assert "relative" not in payload["error"], "absolute missing path should not get the relative-path hint"


def test_collect_evidence_relative_target_hint() -> None:
    payload = collect_evidence("no/such/relative/path")
    assert "error" in payload
    assert "absolute path" in payload["error"]


def test_collect_evidence_rejects_file_target_instead_of_reporting_clean(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(tmp_path))
    model = tmp_path / "model.pkl"
    model.write_bytes(b"cos\nsystem\n.")

    payload = collect_evidence(str(model))

    assert "error" in payload
    assert "directories only" in payload["error"]


@pytest.mark.skipif(importlib.util.find_spec("mcp") is None, reason="mcp extra not installed")
def test_scan_evidence_tool_registers() -> None:
    import asyncio

    from mcp.server.fastmcp import FastMCP

    from rowan import mcp_server

    # main() would block on stdio; replicate its registration step and check
    # the tool is present with the documented name.
    server = FastMCP("rowan-test")
    server.tool()(mcp_server.collect_evidence)
    tools = asyncio.run(server.list_tools())
    assert [t.name for t in tools] == ["collect_evidence"]


def test_collect_evidence_rejects_target_outside_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    (tmp_path / "allowed").mkdir()
    other = _write_vulnerable_app(tmp_path)
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(tmp_path / "allowed"))

    payload = collect_evidence(str(other))

    assert "outside the allowed roots" in payload["error"]
    assert "findings" not in payload


def test_collect_evidence_times_out(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(tmp_path))
    monkeypatch.setenv("ROWAN_MCP_TIMEOUT", "0.01")

    payload = collect_evidence(str(_write_vulnerable_app(tmp_path)))

    assert payload == {"error": "scan timed out after 0.01s (ROWAN_MCP_TIMEOUT)"}


def test_collect_evidence_bad_timeout_is_an_error(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(tmp_path))
    monkeypatch.setenv("ROWAN_MCP_TIMEOUT", "ten")

    payload = collect_evidence(str(_write_vulnerable_app(tmp_path)))

    assert "not a number" in payload["error"]


def test_collect_evidence_rejects_symlink_escaping_roots(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "link").symlink_to(_write_vulnerable_app(tmp_path), target_is_directory=True)
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(allowed))

    payload = collect_evidence(str(allowed / "link"))

    assert "outside the allowed roots" in payload["error"]


def test_scanned_repo_cannot_hide_files_from_mcp(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The MCP server scans repositories an agent was handed, so the repo's
    own .rowanignore must not hide files from it (the --ci trust rule)."""
    import os
    import pickle

    class _Evil:
        def __reduce__(self):
            return (os.system, ("id",))

    (tmp_path / "weights").mkdir()
    (tmp_path / "weights" / "model.pkl").write_bytes(pickle.dumps(_Evil()))
    (tmp_path / ".rowanignore").write_text("weights/\n", encoding="utf-8")
    monkeypatch.setenv("ROWAN_MCP_ROOTS", str(tmp_path))
    payload = collect_evidence(str(tmp_path))

    assert any(f["rule_id"] == "MFV-PICKLE-001" for f in payload["findings"]), payload["findings"]

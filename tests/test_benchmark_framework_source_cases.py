"""Version-pinned framework implementation pair benchmark."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "benchmark" / "ground_truth" / "framework_source_cases"


def _load_benchmark_module():
    spec = importlib.util.spec_from_file_location(
        "benchmark_framework_source_cases", ROOT / "scripts" / "benchmark.py"
    )
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_framework_source_cases"] = module
    spec.loader.exec_module(module)
    return module


def test_source_pair_is_pinned_and_complete():
    cases = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))["cases"]
    assert {case["id"] for case in cases} == {
        "CVE-2025-65106",
        "CVE-2025-68664",
        "CVE-2026-34070",
        "CVE-2026-40087",
    }
    for case in cases:
        for key in ("vulnerable_commit", "fixed_commit"):
            assert len(case[key]) == 40
        assert (CORPUS / case["vulnerable"]).is_file()
        assert (CORPUS / case["fixed"]).is_file()


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep binary is required"
)
def test_source_pair_detects_only_vulnerable_implementation():
    report = _load_benchmark_module().run_framework_source_cases(CORPUS)
    assert not report["degraded"]
    assert report["hits"] == report["total"] == 4
    assert report["false_positives"] == 0
    assert report["ok"] is True

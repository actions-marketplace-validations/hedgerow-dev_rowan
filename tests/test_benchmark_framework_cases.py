"""Tests for the paired framework vulnerability benchmark corpus."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

ROOT = Path(__file__).parent.parent
CORPUS = ROOT / "benchmark" / "ground_truth" / "framework_cases"


def _load_benchmark_module():
    script_path = ROOT / "scripts" / "benchmark.py"
    spec = importlib.util.spec_from_file_location("benchmark_framework_cases", script_path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["benchmark_framework_cases"] = module
    spec.loader.exec_module(module)
    return module


def test_manifest_has_nine_complete_unique_pairs():
    manifest = json.loads((CORPUS / "manifest.json").read_text(encoding="utf-8"))
    cases = manifest["cases"]
    assert len(cases) == 9
    assert len({case["id"] for case in cases}) == 9
    for case in cases:
        assert (CORPUS / case["vulnerable"]).is_file()
        assert (CORPUS / case["fixed"]).is_file()


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(), reason="Opengrep binary is required"
)
def test_framework_pair_benchmark_is_complete_and_clean():
    report = _load_benchmark_module().run_framework_cases(CORPUS)
    assert not report["degraded"]
    assert report["hits"] == report["total"] == 9
    assert report["recall"] == 1.0
    assert report["false_positives"] == 0
    assert report["ok"] is True

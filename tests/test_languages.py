"""Canonical language registry and fail-closed scan scope tests."""

from __future__ import annotations

import pytest

from rowan.config import ScanConfig
from rowan.languages import LANGUAGE_REGISTRY, normalize_languages
from rowan.passes.file_scan import LANGUAGE_EXTENSIONS
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter


def test_scanners_expose_every_canonical_language() -> None:
    supported = set(LANGUAGE_REGISTRY)

    assert set(LANGUAGE_EXTENSIONS) == supported
    assert set(OpengrepAdapter._LANG_EXTENSIONS) == supported
    assert set(OpengrepAdapter._LANG_INCLUDE_GLOBS) == supported


def test_registry_preserves_engine_specific_matching_surfaces() -> None:
    assert LANGUAGE_EXTENSIONS["python"] == [".py", ".pyi"]
    assert OpengrepAdapter._LANG_EXTENSIONS["python"] == (".py",)
    assert LANGUAGE_EXTENSIONS["terraform"] == [".tf", ".tfvars"]
    assert OpengrepAdapter._LANG_EXTENSIONS["terraform"] == (".tf",)
    assert LANGUAGE_EXTENSIONS["dockerfile"] == ["Dockerfile", ".dockerfile"]
    assert OpengrepAdapter._LANG_EXACT_NAMES["dockerfile"] == ("dockerfile",)


def test_language_names_are_canonicalized(tmp_path) -> None:
    assert normalize_languages([" Python ", "JAVASCRIPT"]) == ["python", "javascript"]
    assert ScanConfig(target=tmp_path, languages=[" Python "]).languages == ["python"]


@pytest.mark.parametrize(
    "languages",
    [[""], ["   "], ["python", "pythn"], ["python", ""], ["unknown"]],
)
def test_scan_config_rejects_invalid_explicit_language_scope(tmp_path, languages) -> None:
    with pytest.raises(ValueError, match="Unsupported language"):
        ScanConfig(target=tmp_path, languages=languages)


@pytest.mark.parametrize("languages", [["python", "pythn"], [""], ["python", ""]])
def test_scan_pipeline_revalidates_mutated_config_before_work(
    tmp_path, languages
) -> None:
    config = ScanConfig(target=tmp_path, no_taint=True, legacy_neuroscan=True)
    config.languages = languages

    with pytest.raises(ValueError, match="Unsupported language"):
        ScanPipeline(config)


def test_empty_language_list_still_means_all_languages(tmp_path) -> None:
    config = ScanConfig(target=tmp_path, languages=[])

    assert config.languages == []

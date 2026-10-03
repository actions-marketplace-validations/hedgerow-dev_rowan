"""Regression checks for the public documentation count gate."""

from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path

SCRIPT_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_doc_counts.py"
SPEC = spec_from_file_location("check_doc_counts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
search_doc_counts = MODULE.search_doc_counts


def test_total_yaml_count_is_not_inferred_from_rule_count_digits(tmp_path):
    readme = tmp_path / "README.md"
    readme.write_text(
        "582 rules across 47 YAML files:\n"
        "- **400 regex rules**: 22 YAML files\n"
        "- **182 taint/Opengrep rules**: 25 YAML files\n",
        encoding="utf-8",
    )

    counts = search_doc_counts(readme)

    assert counts["total_yaml_files"][0] == 47
    assert counts["regex_yaml_files"][0] == 22
    assert counts["taint_yaml_files"][0] == 25

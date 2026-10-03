"""Tests for AST-based call-graph reachability (rowan.core.reachability)."""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

from rowan.core.reachability import (
    collect_reachable_calls,
    extract_import_aliases,
    is_package_reachable,
    resolve_calls,
)


def _aliases(src: str) -> dict[str, str]:
    return extract_import_aliases(ast.parse(src))


def _calls(src: str) -> set[str]:
    tree = ast.parse(src)
    return resolve_calls(tree, extract_import_aliases(tree))


class TestExtractImportAliases:
    def test_plain_import(self):
        assert _aliases("import torch") == {"torch": "torch"}

    def test_import_with_alias(self):
        assert _aliases("import torch as t") == {"t": "torch"}

    def test_from_import(self):
        assert _aliases("from torch import load") == {"load": "torch.load"}

    def test_from_import_with_alias(self):
        assert _aliases("from torch import load as tl") == {"tl": "torch.load"}

    def test_from_import_nested_module(self):
        aliases = _aliases("from transformers import AutoModel")
        assert aliases == {"AutoModel": "transformers.AutoModel"}

    def test_relative_import_skipped(self):
        # Relative imports resolve to local modules, not third-party packages.
        assert _aliases("from . import helpers") == {}
        assert _aliases("from .utils import foo") == {}

    def test_star_import_skipped(self):
        assert _aliases("from torch import *") == {}


class TestResolveCalls:
    def test_module_attribute_call(self):
        assert "torch.load" in _calls("import torch\ntorch.load('x')")

    def test_aliased_module_call(self):
        assert "torch.load" in _calls("import torch as t\nt.load('x')")

    def test_from_import_bare_call_resolves_qualified(self):
        # `load(...)` after `from torch import load` must resolve back to
        # "torch.load", not stay as the ambiguous bare name "load".
        calls = _calls("from torch import load\nload('x')")
        assert "torch.load" in calls
        assert "load" not in calls

    def test_unrelated_call_not_falsely_qualified(self):
        # A local function also named `load`, with no torch import, must
        # not be confused with torch.load.
        calls = _calls("def load(x): pass\nload(1)")
        assert "torch.load" not in calls

    def test_nested_attribute_call(self):
        calls = _calls("import mlflow\nmlflow.pyfunc.load_model('x')")
        assert "mlflow.pyfunc.load_model" in calls


class TestIsPackageReachable:
    def test_qualified_match(self):
        reachable, evidence = is_package_reachable(
            "torch", ["torch.load", "load"], {"torch.load"}
        )
        assert reachable is True
        assert evidence == "torch.load"

    def test_no_match(self):
        reachable, _ = is_package_reachable(
            "torch", ["torch.load", "load"], {"torch.tensor", "torch.nn.Linear"}
        )
        assert reachable is False

    def test_package_used_but_not_vulnerable_function(self):
        # Regression: importing/using a package at all must NOT count as
        # "reachable" for a specific CVE'd function within it.
        reachable, _ = is_package_reachable("torch", ["torch.load"], {"torch.tensor"})
        assert reachable is False

    def test_bare_entry_scoped_suffix_match(self):
        # transformers exposes dozens of Auto* classes that all share
        # .from_pretrained() -- enumerating every class name isn't tractable,
        # so a bare "from_pretrained" entry should match any call resolved
        # into the transformers namespace ending in that method name.
        reachable, evidence = is_package_reachable(
            "transformers",
            ["from_pretrained"],
            {"transformers.AutoModelForCausalLM.from_pretrained"},
        )
        assert reachable is True
        assert evidence == "transformers.AutoModelForCausalLM.from_pretrained"

    def test_bare_entry_suffix_match_does_not_cross_packages(self):
        # The scoped suffix match must still require the package prefix --
        # a from_pretrained call resolved into an unrelated package must not
        # satisfy transformers' bare entry.
        reachable, _ = is_package_reachable(
            "transformers", ["from_pretrained"], {"sentence_transformers.SomeModel.from_pretrained"}
        )
        assert reachable is False

    def test_bare_entry_alone_does_not_match(self):
        # Bare "load" should never literally appear in resolved_calls (it's
        # always qualified by resolve_calls), so a bare-only vuln_funcs list
        # only matches if some other qualified path catches it.
        reachable, _ = is_package_reachable("torch", ["load"], {"load"})
        assert reachable is False


class TestCollectReachableCalls:
    def test_end_to_end_reachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import torch\nmodel = torch.load('m.pt')\n")
            calls = collect_reachable_calls([root / "app.py"])
            assert "torch.load" in calls

    def test_end_to_end_unreachable(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("import torch\nx = torch.tensor([1])\n")
            calls = collect_reachable_calls([root / "app.py"])
            assert "torch.load" not in calls

    def test_skips_unparseable_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "broken.py").write_text("def f(:\n  pass")
            (root / "ok.py").write_text("import torch\ntorch.load('m')\n")
            calls = collect_reachable_calls([root / "broken.py", root / "ok.py"])
            assert "torch.load" in calls

    def test_indirect_import_via_from(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "app.py").write_text("from torch import load\nload('m.pt')\n")
            calls = collect_reachable_calls([root / "app.py"])
            assert "torch.load" in calls


def test_non_python_ecosystem_not_marked_reachable(tmp_path):
    """SC-10: the call graph is Python-only, so a Python requests.get() must
    not make the npm package `requests` reachable."""
    from rowan.core.findings import Category, Finding, Severity
    from rowan.passes.sca import SCAPass

    (tmp_path / "app.py").write_text("import requests\n\ndef f(p):\n    return requests.get(p)\n")

    def finding(ecosystem):
        return Finding(rule_id="SCA-x", message="", severity=Severity.HIGH, category=Category.SUPPLY_CHAIN,
                       file_path="manifest", start_line=0, confidence=0.8, engine="depguard",
                       metadata={"package": "requests", "ecosystem": ecosystem, "version": "2.0.0", "details": ""})

    npm, pypi = finding("npm"), finding("PyPI")
    SCAPass()._apply_reachability([npm, pypi], tmp_path)

    assert "reachability" not in npm.metadata
    assert pypi.metadata.get("reachability") == "reachable"

"""Typed sanitizer registry (BACKLOG CN-04: TE-11, TE-23, RT-05, XF-14)."""

from __future__ import annotations

from pathlib import Path

from rowan.core.findings import Category
from rowan.core.rules import load_neuroscan_rules
from rowan.core.sanitizers import (
    call_sanitizers,
    sanitizer_matches,
    sanitizers_for,
    shape_sanitizers,
)

RULES_DIR = Path(__file__).parent.parent / "rules"


class TestTypedEntries:
    def test_entries_are_split_by_kind(self):
        calls = {s.pattern for s in call_sanitizers(Category.COMMAND_INJECTION)}
        shapes = {s.pattern for s in shape_sanitizers(Category.COMMAND_INJECTION)}
        assert any("shlex" in p for p in calls)
        assert any("shell" in p for p in shapes)
        assert not (calls & shapes)

    def test_every_category_compiles(self):
        for category in Category:
            for s in sanitizers_for(category):
                assert s.regex.pattern


class TestWindowCorrelation:
    """A shape sanitizer (`shell=False`, `subprocess.run([`) on an unrelated
    line must not suppress a finding on another line (TE-11)."""

    def test_shape_sanitizer_on_unrelated_line_does_not_match(self):
        window = [
            "subprocess.run(['ls', '-l'], shell=False)",
            "os.system(cmd)",
        ]
        assert not sanitizer_matches(
            sanitizers_for(Category.COMMAND_INJECTION), window, "os.system(cmd)"
        )

    def test_shape_sanitizer_later_in_the_same_call_matches(self):
        window = ["resp.set_cookie(", "    'k', v,", "    httponly=True,", ")", "other(x)"]
        sanitizer = sanitizers_for(
            Category.COMMAND_INJECTION
        )  # any category; pattern below is ad hoc
        import re

        from rowan.core.sanitizers import Sanitizer

        httponly = (Sanitizer(r"httponly\s*=", "shape", re.compile(r"httponly\s*=")),)
        assert sanitizer_matches(httponly, window, "resp.set_cookie(")
        assert sanitizer_matches(httponly, window, "    'k', v,"), (
            "continuation line of the same call"
        )
        assert not sanitizer_matches(httponly, window, "other(x)")
        assert sanitizer  # keep the registry import exercised

    def test_shape_sanitizer_on_the_finding_line_matches(self):
        line = "subprocess.run(cmd, shell=False)"
        assert sanitizer_matches(sanitizers_for(Category.COMMAND_INJECTION), [line], line)

    def test_shape_sanitizer_on_a_line_sharing_the_variable_matches(self):
        window = ["safe = torch.load(p, weights_only=True)", "model = unpickle(safe)"]
        assert sanitizer_matches(
            sanitizers_for(Category.DESERIALIZATION), window, "model = unpickle(safe)"
        )

    def test_call_sanitizer_still_needs_a_shared_identifier(self):
        window = ["fmt = shlex.quote(target_format)", "subprocess.run(cmd, shell=True)"]
        assert not sanitizer_matches(
            sanitizers_for(Category.COMMAND_INJECTION), window, "subprocess.run(cmd, shell=True)"
        )


class TestLegacyEngineUsesTheSameLogic:
    def test_shell_false_elsewhere_in_window_no_longer_suppresses(self, tmp_path):
        src = tmp_path / "app.py"
        src.write_text(
            "import subprocess\n"
            "import os\n\n"
            "def run(cmd, listing):\n"
            "    subprocess.run(listing, shell=False)\n"
            "    os.system(cmd)\n",
            encoding="utf-8",
        )
        rules = load_neuroscan_rules(RULES_DIR / "neuroscan.yaml")
        rule = next(r for r in rules if r.metadata.name == "os.system usage")
        assert rule.check(src), "shell=False on the listing call must not clear os.system(cmd)"

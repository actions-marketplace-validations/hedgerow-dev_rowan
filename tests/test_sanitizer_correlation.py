"""Regression tests for sanitizer-window variable correlation.

Both the legacy regex engine (NeuroScanRule._sanitizer_in_window) and the
default engine's enrichment pass (EnrichmentPass._suppress_sanitizer_window)
used to suppress a finding if a category sanitizer pattern (e.g.
shlex.quote(...)) appeared ANYWHERE in a +/-10 line window around the match,
regardless of which variable it was applied to. Found scanning a real
deliberately-vulnerable app (ModelForge / "Damn Vulnerable AI/ML"): a command
injection in `convert_model` was missed because `shlex.quote(target_format)`
appeared a few lines above `subprocess.run(cmd, shell=True)`, even though
`cmd` (built from the unquoted `src`/`artifact_name`) was never the value
passed to shlex.quote() -- confirmed exploitable per the app's own labeled
ground truth. Both suppression mechanisms now require the sanitizer's own
line to share an identifier with the finding's line for argument-taking
sanitizer patterns (those whose source ends in an unclosed `\\(`); call-shape
sanitizers (shell=False, PreparedStatement, ...) are unaffected -- their mere
presence is a meaningful signal regardless of variable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.rules import _line_identifiers, load_neuroscan_rules
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import EnrichmentPass
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"


def test_line_identifiers_excludes_keywords_and_stopwords():
    ids = _line_identifiers("proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)")
    assert "cmd" in ids
    assert "subprocess" in ids
    assert "shell" not in ids  # stopword
    assert "True" not in ids  # keyword


class TestLegacyEngineSanitizerCorrelation:
    """NeuroScanRule.check() -- rules/neuroscan.yaml::NS-INJECT-003."""

    def test_shlex_quote_on_unrelated_variable_does_not_suppress(self, tmp_path):
        src = tmp_path / "convert.py"
        src.write_text(
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def convert_model(artifact_name, target_format):\n"
            "    src = artifact_name\n"
            "    fmt = shlex.quote(target_format)\n"
            "    cmd = f'echo {src} to {fmt}'\n"
            "    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n"
            "    return proc.stdout\n",
            encoding="utf-8",
        )
        rules = load_neuroscan_rules(RULES_DIR / "neuroscan.yaml")
        rule = next(r for r in rules if r.metadata.id == "NS-INJECT-003")
        assert rule.check(src), (
            "shlex.quote(target_format) must not suppress a finding on the "
            "unrelated, unquoted `cmd` reaching subprocess(shell=True)"
        )

    def test_shlex_quote_on_the_actual_sink_variable_still_suppresses(self, tmp_path):
        src = tmp_path / "safe.py"
        src.write_text(
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def run_safe(cmd):\n"
            "    safe_cmd = shlex.quote(cmd)\n"
            "    subprocess.run(safe_cmd, shell=True)\n",
            encoding="utf-8",
        )
        rules = load_neuroscan_rules(RULES_DIR / "neuroscan.yaml")
        rule = next(r for r in rules if r.metadata.id == "NS-INJECT-003")
        assert rule.check(src) == [], (
            "shlex.quote(cmd) assigned to safe_cmd, which IS the sink variable, "
            "must still suppress the finding"
        )

    def test_call_shape_sanitizer_still_suppresses_regardless_of_variable(self, tmp_path):
        src = tmp_path / "mixed.py"
        src.write_text(
            "import subprocess\n"
            "\n"
            "def a(unrelated):\n"
            "    subprocess.run(['ls', unrelated], shell=False)\n"
            "\n"
            "def b(cmd):\n"
            "    subprocess.run(cmd, shell=True)\n",
            encoding="utf-8",
        )
        rules = load_neuroscan_rules(RULES_DIR / "neuroscan.yaml")
        rule = next(r for r in rules if r.metadata.id == "NS-INJECT-003")
        # shell=False is a call-shape sanitizer (no captured argument) -- its
        # presence nearby is unaffected by the variable-correlation fix.
        assert rule.check(src) == [], (
            "a call-shape sanitizer (shell=False) must still suppress "
            "regardless of which function/variable it appears near"
        )


@pytest.mark.skipif(
    not OpengrepAdapter().is_installed(),
    reason="Opengrep binary not installed; this test needs the default (non-legacy) engine path.",
)
class TestDefaultEngineSanitizerCorrelation:
    """EnrichmentPass._suppress_sanitizer_window via the real default pipeline."""

    def test_shlex_quote_on_unrelated_variable_does_not_suppress(self, tmp_path):
        (tmp_path / "convert.py").write_text(
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def convert_model(artifact_name, target_format):\n"
            "    src = artifact_name\n"
            "    fmt = shlex.quote(target_format)\n"
            "    cmd = f'echo {src} to {fmt}'\n"
            "    proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)\n"
            "    return proc.stdout\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path, no_taint=True, no_sca=True, languages=["python"]
        )
        result = ScanPipeline(config).run()
        cmdi = [f for f in result.findings if "CMDI" in f.rule_id or "INJECT-003" in f.rule_id]
        assert cmdi, (
            "shlex.quote(target_format) must not suppress a finding on the "
            "unrelated, unquoted `cmd` reaching subprocess(shell=True), got: "
            f"{[(f.rule_id, f.start_line) for f in result.findings]}"
        )

    def test_shlex_quote_on_the_actual_sink_variable_still_suppresses(self, tmp_path):
        (tmp_path / "safe.py").write_text(
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def run_safe(cmd):\n"
            "    safe_cmd = shlex.quote(cmd)\n"
            "    subprocess.run(safe_cmd, shell=True)\n",
            encoding="utf-8",
        )
        config = ScanConfig(
            target=tmp_path, no_taint=True, no_sca=True, languages=["python"]
        )
        result = ScanPipeline(config).run()
        cmdi = [f for f in result.findings if "CMDI" in f.rule_id or "INJECT-003" in f.rule_id]
        assert cmdi == [], (
            "shlex.quote(cmd) assigned to safe_cmd, which IS the sink variable, "
            f"must still suppress the finding, got: {[(f.rule_id, f.start_line) for f in cmdi]}"
        )


def _sanitizer_window_context(rule_id: str, category: Category) -> ScanContext:
    """Minimal ScanContext carrying just enough `conversion_manifest` shape
    for `EnrichmentPass._suppress_sanitizer_window` to treat `rule_id` as a
    'sanitizer' residual finding for `category`."""
    config = ScanConfig(target=Path("."))
    return ScanContext(
        target_path=Path("."),
        config=config,
        result=ScanResult(),
        metadata={
            "conversion_manifest": {
                "rule_map": {
                    rule_id: {"residual": ["sanitizer"], "category": category.value},
                }
            }
        },
    )


class TestSanitizerWindowDominanceVsProximity:
    """GitHub issue #124: `_suppress_sanitizer_window` prefers real dominance
    (`collect_dominating_candidates`, shared with `guard_clause.py`'s issue
    #160 fix) over the old raw ±10-line text-proximity window, falling back
    to the proximity window only when the AST can't be parsed or no
    enclosing function is found. Exercises `EnrichmentPass` directly against
    a hand-built `ScanContext`, so no Opengrep binary is required."""

    RULE_ID = "TEST-CMDI-DOMINANCE"

    def _finding(self, file_path: Path, sink_line: int) -> Finding:
        return Finding(
            rule_id=self.RULE_ID,
            message="command injection",
            severity=Severity.HIGH,
            category=Category.COMMAND_INJECTION,
            file_path=str(file_path),
            start_line=sink_line,
            engine="opengrep",
            confidence=0.9,
        )

    def test_dominating_sanitizer_beyond_old_window_now_suppresses(self, tmp_path):
        """Positive control: `shlex.quote(cmd)` is an unconditional prior
        sibling of the sink inside the same function -- genuinely dominates
        -- but sits 13 lines away, well outside the old ±10-line window.
        The old proximity-only check would have missed it; real dominance
        must now suppress."""
        filler = "".join(f"    x{i} = {i}\n" for i in range(1, 13))
        src = (
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def run(cmd, flag):\n"
            "    safe = shlex.quote(cmd)\n"
            f"{filler}"
            "    subprocess.run(cmd, shell=True)\n"
        )
        path = tmp_path / "dominates_far.py"
        path.write_text(src, encoding="utf-8")
        lines = src.splitlines()
        sink_line = next(i for i, ln in enumerate(lines, 1) if "subprocess.run" in ln)
        sanitizer_line = next(i for i, ln in enumerate(lines, 1) if "shlex.quote" in ln)
        assert sink_line - sanitizer_line > 10, "test setup must exceed the old window"

        ep = EnrichmentPass()
        ctx = _sanitizer_window_context(self.RULE_ID, Category.COMMAND_INJECTION)
        result = ep._suppress_sanitizer_window([self._finding(path, sink_line)], ctx)
        assert result == [], (
            "a sanitizer that genuinely dominates the sink, even >10 lines "
            f"away, must now suppress -- got {result}"
        )

    def test_sanitizer_in_non_dominating_branch_within_old_window_still_flags(self, tmp_path):
        """The actual false-negative-closing regression test: `shlex.quote
        (cmd)` sits in the `if flag:` arm, only 3 lines from the sink -- well
        within the old ±10-line window, which would have suppressed this.
        But the sink is a sibling AFTER the if/else, reachable whether or
        not `flag` is truthy, so the sanitizer does NOT dominate it. Real
        dominance must leave this finding un-suppressed."""
        src = (
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def run(cmd, flag):\n"
            "    if flag:\n"
            "        safe = shlex.quote(cmd)\n"
            "    else:\n"
            "        pass\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        path = tmp_path / "non_dominating_branch.py"
        path.write_text(src, encoding="utf-8")
        lines = src.splitlines()
        sink_line = next(i for i, ln in enumerate(lines, 1) if "subprocess.run" in ln)
        sanitizer_line = next(i for i, ln in enumerate(lines, 1) if "shlex.quote" in ln)
        assert sink_line - sanitizer_line <= 10, "test setup must be inside the old window"

        ep = EnrichmentPass()
        ctx = _sanitizer_window_context(self.RULE_ID, Category.COMMAND_INJECTION)
        result = ep._suppress_sanitizer_window([self._finding(path, sink_line)], ctx)
        assert len(result) == 1, (
            "a sanitizer sitting in the untaken arm of an if/else must not "
            f"suppress a sink that's reachable either way -- got {result}"
        )

    def test_syntax_error_falls_back_to_proximity_window(self, tmp_path):
        """Fallback path (a): the file has a genuine `SyntaxError`. Per this
        codebase's "over-flagging accepted, silent false-negative not"
        stance, this must fall back to the old ±10-line proximity check
        exactly, not silently suppress nothing and not silently suppress
        everything."""
        src = (
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "def run(cmd\n"  # missing closing paren -- SyntaxError
            "    safe = shlex.quote(cmd)\n"
            "    subprocess.run(cmd, shell=True)\n"
        )
        path = tmp_path / "broken_syntax.py"
        path.write_text(src, encoding="utf-8")
        with pytest.raises(SyntaxError):
            import ast as _ast

            _ast.parse(src)
        lines = src.splitlines()
        sink_line = next(i for i, ln in enumerate(lines, 1) if "subprocess.run" in ln)

        ep = EnrichmentPass()
        ctx = _sanitizer_window_context(self.RULE_ID, Category.COMMAND_INJECTION)
        result = ep._suppress_sanitizer_window([self._finding(path, sink_line)], ctx)
        assert result == [], (
            "a SyntaxError file must fall back to the old proximity window, "
            f"which would have suppressed this nearby sanitizer -- got {result}"
        )

    def test_module_level_finding_falls_back_to_proximity_window(self, tmp_path):
        """Fallback path (b): module-level code has no enclosing function,
        so there's no dominance structure to compute over -- must fall back
        to the proximity window exactly as before."""
        src = (
            "import shlex\n"
            "import subprocess\n"
            "\n"
            "cmd = get_input()\n"
            "safe = shlex.quote(cmd)\n"
            "subprocess.run(cmd, shell=True)\n"
        )
        path = tmp_path / "module_level.py"
        path.write_text(src, encoding="utf-8")
        lines = src.splitlines()
        sink_line = next(i for i, ln in enumerate(lines, 1) if "subprocess.run" in ln)

        ep = EnrichmentPass()
        ctx = _sanitizer_window_context(self.RULE_ID, Category.COMMAND_INJECTION)
        result = ep._suppress_sanitizer_window([self._finding(path, sink_line)], ctx)
        assert result == [], (
            "module-level code has no enclosing function to compute "
            f"dominance over, so this must fall back to the proximity "
            f"window and suppress -- got {result}"
        )


class TestPerRuleSanitizersOnDefaultEngine:
    """A rule's own `sanitizers:` list used to work only under the legacy
    NeuroScan engine. On the default (Opengrep) path, `residual: sanitizer`
    made `_suppress_sanitizer_window` apply the finding's *category* shared
    sanitizers and nothing else, so the rule's own list was silently dropped
    -- and a rule in a category with no shared set (config, crypto, auth)
    bailed out before any sanitizer ran at all. The converter now writes the
    list into `_manifest.json` and `_suppress_sanitizer_window` unions it with
    the category's.
    """

    RULE_ID = "TEST-COOKIE-HTTPONLY"

    def _context(self, sanitizers: list[str] | None) -> ScanContext:
        info: dict = {"residual": ["sanitizer"], "category": Category.CONFIG.value}
        if sanitizers is not None:
            info["sanitizers"] = sanitizers
        return ScanContext(
            target_path=Path("."),
            config=ScanConfig(target=Path(".")),
            result=ScanResult(),
            metadata={"conversion_manifest": {"rule_map": {self.RULE_ID: info}}},
        )

    def _finding(self, file_path: Path, line: int) -> Finding:
        return Finding(
            rule_id=self.RULE_ID,
            message="cookie without httponly",
            severity=Severity.MEDIUM,
            category=Category.CONFIG,
            file_path=str(file_path),
            start_line=line,
            engine="opengrep",
            confidence=0.7,
        )

    SAFE_SOURCE = (
        "def login(user):\n"
        "    resp = make_response(redirect('/'))\n"
        "    resp.set_cookie(\n"
        "        'session',\n"
        "        issue_token(user.id),\n"
        "        httponly=True,\n"
        "    )\n"
        "    return resp\n"
    )

    def test_rule_sanitizer_suppresses_on_default_engine(self, tmp_path):
        src = tmp_path / "views.py"
        src.write_text(self.SAFE_SOURCE, encoding="utf-8")
        context = self._context([r"(?i)httponly\s*="])
        kept = EnrichmentPass()._suppress_sanitizer_window(
            [self._finding(src, 3)], context
        )
        assert kept == [], (
            "the rule's own `httponly=` sanitizer must suppress the finding "
            "three lines above it on the default engine path"
        )

    def test_without_manifest_sanitizers_the_finding_survives(self, tmp_path):
        """Negative control: `config` has no category-level sanitizer set, so
        with the rule's own list absent nothing suppresses -- which is exactly
        the pre-fix behaviour this guards against regressing to."""
        src = tmp_path / "views.py"
        src.write_text(self.SAFE_SOURCE, encoding="utf-8")
        context = self._context(None)
        kept = EnrichmentPass()._suppress_sanitizer_window(
            [self._finding(src, 3)], context
        )
        assert [f.rule_id for f in kept] == [self.RULE_ID]

    def test_rule_sanitizer_does_not_suppress_the_vulnerable_form(self, tmp_path):
        src = tmp_path / "views.py"
        src.write_text(
            "def login(user):\n"
            "    resp = make_response(redirect('/'))\n"
            "    resp.set_cookie('session', issue_token(user.id))\n"
            "    return resp\n",
            encoding="utf-8",
        )
        context = self._context([r"(?i)httponly\s*="])
        kept = EnrichmentPass()._suppress_sanitizer_window(
            [self._finding(src, 3)], context
        )
        assert [f.rule_id for f in kept] == [self.RULE_ID]

    def test_uncompilable_rule_sanitizer_is_skipped_not_fatal(self, tmp_path):
        src = tmp_path / "views.py"
        src.write_text(self.SAFE_SOURCE, encoding="utf-8")
        context = self._context(["(unclosed", r"(?i)httponly\s*="])
        kept = EnrichmentPass()._suppress_sanitizer_window(
            [self._finding(src, 3)], context
        )
        assert kept == []

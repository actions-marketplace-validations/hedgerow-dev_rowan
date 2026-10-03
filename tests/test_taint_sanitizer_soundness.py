"""Regression tests for taint-rule sanitizer soundness (GitHub issue #84).

Several `pattern-sanitizers` entries used to match a call *shape* (e.g.
`re.sub(...)`, `strings.ReplaceAll(...)`) regardless of the caller-supplied
arguments, so applying the operation to the tainted value with unrelated
arguments still cleared taint even though the actual threat (an embedded
newline, an LDAP metacharacter, a ".." path segment) passed through
untouched. Each test here reproduces the exact false-negative shape and
confirms it now fires, alongside a companion case proving the still-sound
sanitizers correctly suppress a real fix.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention for tests that need a live scan -- CI does not
install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.enrichment import EnrichmentPass
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path: Path, rule_file: str, source: str, rule_id: str) -> list:
    fp = tmp_path / "target.py"
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id]


def _scan_and_enrich(tmp_path: Path, rule_file: str, source: str, rule_id: str) -> list:
    """Like `_scan`, but also runs the raw findings through EnrichmentPass --
    the guard-clause post-filter (GitHub issue #160) is an enrichment step,
    not part of the Opengrep scan itself, so testing its effect requires the
    full scan-then-enrich pipeline."""
    findings = _scan(tmp_path, rule_file, source, rule_id)
    ctx = type("Ctx", (), {
        "target_path": tmp_path,
        "config": ScanConfig(target=tmp_path),
        "result": ScanResult(findings=findings),
        "metadata": {},
    })()
    EnrichmentPass().run(ctx)
    return ctx.result.findings


def _scan_lang(
    tmp_path: Path, rule_file: str, source: str, rule_id: str, *, language: str, filename: str
) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=[language])
    return [f for f in findings if f.rule_id == rule_id]


class TestLogInjectionSanitizerSoundness:
    """TNT-LOG-001 (rules/python_taint.yaml)."""

    def test_unrelated_re_sub_no_longer_masks_log_injection(self, tmp_path):
        """re.sub applied to the tainted value with args unrelated to \\n/\\r
        must NOT suppress the finding (it used to)."""
        src = (
            "import logging\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    val = request.args.get('x')\n"
            "    val = re.sub(r'foo', 'bar', val)\n"
            "    logging.info(val)\n"
        )
        findings = _scan(tmp_path, "python_taint.yaml", src, "TNT-LOG-001")
        assert findings, "re.sub with unrelated args must not suppress TNT-LOG-001"

    def test_strip_no_longer_masks_embedded_newline(self, tmp_path):
        """.strip() only trims edges; an embedded newline payload must still
        be flagged (it used to be silently suppressed)."""
        src = (
            "import logging\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    val = request.args.get('x')\n"
            "    val = val.strip()\n"
            "    logging.info(val)\n"
        )
        findings = _scan(tmp_path, "python_taint.yaml", src, "TNT-LOG-001")
        assert findings, ".strip() must not suppress TNT-LOG-001 (embedded newlines pass through)"

    def test_repr_still_suppresses(self, tmp_path):
        """repr() unconditionally escapes control characters -- still sound,
        must still suppress the finding."""
        src = (
            "import logging\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    val = request.args.get('x')\n"
            "    val = repr(val)\n"
            "    logging.info(val)\n"
        )
        findings = _scan(tmp_path, "python_taint.yaml", src, "TNT-LOG-001")
        assert not findings, "repr() is a sound sanitizer and should still suppress TNT-LOG-001"

    def test_bound_newline_replace_still_suppresses(self, tmp_path):
        """$STR.replace('\\n', ...) is pinned to the actual threat character
        -- still sound, must still suppress the finding."""
        src = (
            "import logging\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    val = request.args.get('x')\n"
            "    val = val.replace('\\n', '')\n"
            "    logging.info(val)\n"
        )
        findings = _scan(tmp_path, "python_taint.yaml", src, "TNT-LOG-001")
        assert not findings, "$STR.replace('\\n', ...) is a sound sanitizer and should still suppress"


class TestSQLiSanitizerSoundness:
    """TNT-SQLI-001 (rules/web_taint.yaml)."""

    def test_unrelated_replace_no_longer_masks_sqli(self, tmp_path):
        src = (
            "from flask import request\n"
            "\n"
            "def handler(cursor):\n"
            "    q = request.args.get('q')\n"
            "    q = q.replace('unrelated', 'x')\n"
            "    cursor.execute(q)\n"
        )
        findings = _scan(tmp_path, "web_taint.yaml", src, "TNT-SQLI-001")
        assert findings, "unrelated .replace() must not suppress TNT-SQLI-001"


class TestPathTraversalSanitizerSoundness:
    """TNT-PATH-001 (rules/web_taint.yaml)."""

    def test_unrelated_replace_no_longer_masks_path_traversal(self, tmp_path):
        src = (
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    p = request.args.get('path')\n"
            "    p = p.replace('unrelated', 'x')\n"
            "    return open(p)\n"
        )
        findings = _scan(tmp_path, "web_taint.yaml", src, "TNT-PATH-001")
        assert findings, "unrelated .replace() must not suppress TNT-PATH-001"

    def test_basename_still_suppresses(self, tmp_path):
        """os.path.basename() strips all directory components regardless of
        argument content -- still sound, must still suppress the finding."""
        src = (
            "import os\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    p = request.args.get('path')\n"
            "    p = os.path.basename(p)\n"
            "    return open(p)\n"
        )
        findings = _scan(tmp_path, "web_taint.yaml", src, "TNT-PATH-001")
        assert not findings, "os.path.basename() is a sound sanitizer and should still suppress"


class TestWeakGuardSanitizersRemoved:
    """GitHub issue #87 -- 'just parses'/'normalizes but doesn't enforce a
    boundary' guards provide no real safety property (successfully parsing a
    string as a URL/IP says nothing about where it points; resolving a path
    to an absolute form says nothing about whether it stays under a root
    directory), so they were removed as sanitizers rather than tightened or
    downgraded (Opengrep's adapter doesn't expose which specific sanitizer
    pattern suppressed a finding, so a targeted confidence downgrade isn't
    implementable; removing accepts the recall trade-off in favor of not
    handing out false assurance)."""

    def test_urlparse_no_longer_masks_ssrf(self, tmp_path):
        """urlparse() only parses a URL's components; it doesn't check
        whether the host is internal/cloud-metadata. Reassigning its result
        back onto the tainted variable (the exact shape that used to clear
        taint) must still be flagged."""
        src = (
            "import requests\n"
            "from urllib.parse import urlparse\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    url = urlparse(url)\n"
            "    return requests.get(url)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "urlparse() must not suppress TNT-SSRF-001 (it validates nothing about the host)"

    def test_path_resolve_no_longer_masks_path_traversal(self, tmp_path):
        """.resolve() produces a clean absolute path but never checks it's
        still under an intended root -- a '../../etc/passwd' payload still
        resolves outside any reasonable base dir and must still be flagged."""
        src = (
            "from pathlib import Path\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    p = Path(request.args.get('path')).resolve()\n"
            "    return open(p)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-PATH-002")
        assert findings, ".resolve() must not suppress TNT-PATH-002 (no root-directory check)"

    def test_go_net_parseip_no_longer_masks_ssrf(self, tmp_path):
        src = (
            'package main\n'
            'import ("net"; "net/http")\n'
            'func handler(r *http.Request) {\n'
            '    url := r.URL.Query().Get("url")\n'
            '    url = net.ParseIP(url).String()\n'
            '    http.Get(url)\n'
            '}\n'
        )
        findings = _scan_lang(
            tmp_path, "go_taint.yaml", src, "tnt-go-ssrf-001", language="go", filename="test.go"
        )
        assert findings, "net.ParseIP(...) must not suppress tnt-go-ssrf-001"

    def test_go_filepath_clean_no_longer_masks_path_traversal(self, tmp_path):
        src = (
            'package main\n'
            'import ("os"; "path/filepath"; "net/http")\n'
            'func handler(r *http.Request) {\n'
            '    p := r.URL.Query().Get("path")\n'
            '    clean := filepath.Clean(p)\n'
            '    os.ReadFile(clean)\n'
            '}\n'
        )
        findings = _scan_lang(
            tmp_path, "go_taint.yaml", src, "tnt-go-path-001", language="go", filename="test.go"
        )
        assert findings, "filepath.Clean(...) must not suppress tnt-go-path-001"

    def test_java_inetaddress_no_longer_masks_ssrf(self, tmp_path):
        src = (
            "import java.net.InetAddress;\n"
            "class C {\n"
            "  void handler(HttpServletRequest req) throws Exception {\n"
            '    String url = req.getParameter("url");\n'
            "    url = InetAddress.getByName(url).toString();\n"
            "    new URL(url).openConnection();\n"
            "  }\n"
            "}\n"
        )
        findings = _scan_lang(
            tmp_path, "java_taint.yaml", src, "tnt-ja-ssrf-001", language="java", filename="Test.java"
        )
        assert findings, "InetAddress.getByName(...) must not suppress tnt-ja-ssrf-001"

    def test_java_path_normalize_no_longer_masks_path_traversal(self, tmp_path):
        src = (
            "import java.nio.file.*;\n"
            "class C {\n"
            "  void handler(HttpServletRequest req) throws Exception {\n"
            '    String p = req.getParameter("path");\n'
            "    Path normalized = Paths.get(p).normalize();\n"
            "    Files.readAllBytes(normalized);\n"
            "  }\n"
            "}\n"
        )
        findings = _scan_lang(
            tmp_path, "java_taint.yaml", src, "tnt-ja-path-001", language="java", filename="Test.java"
        )
        assert findings, "(Path $P).normalize() must not suppress tnt-ja-path-001"

    def test_csharp_new_uri_no_longer_masks_ssrf(self, tmp_path):
        src = (
            "class C {\n"
            "  async void Handler() {\n"
            '    var url = Request.Query["url"];\n'
            "    url = new Uri(url).ToString();\n"
            "    await new HttpClient().GetStringAsync(url);\n"
            "  }\n"
            "}\n"
        )
        findings = _scan_lang(
            tmp_path, "csharp_taint.yaml", src, "tnt-cs-ssrf-001", language="csharp", filename="Test.cs"
        )
        assert findings, "new Uri(...) must not suppress tnt-cs-ssrf-001"

    def test_csharp_path_getfullpath_no_longer_masks_path_traversal(self, tmp_path):
        src = (
            "class C {\n"
            "  void Handler() {\n"
            '    var p = Request.Query["path"];\n'
            "    var full = Path.GetFullPath(p);\n"
            "    File.ReadAllText(full);\n"
            "  }\n"
            "}\n"
        )
        findings = _scan_lang(
            tmp_path, "csharp_taint.yaml", src, "tnt-cs-path-001", language="csharp", filename="Test.cs"
        )
        assert findings, "Path.GetFullPath(...) must not suppress tnt-cs-path-001"

    def test_js_new_url_no_longer_masks_ssrf(self, tmp_path):
        src = (
            "function handler(req) {\n"
            "  let url = req.query.url;\n"
            "  url = new URL(url).toString();\n"
            "  return fetch(url);\n"
            "}\n"
        )
        findings = _scan_lang(
            tmp_path, "javascript_taint.yaml", src, "tnt-js-ssrf-001",
            language="javascript", filename="test.js",
        )
        assert findings, "new URL(...) must not suppress tnt-js-ssrf-001"

    def test_js_path_resolve_no_longer_masks_path_traversal(self, tmp_path):
        src = (
            "const path = require('path');\n"
            "const fs = require('fs');\n"
            "function handler(req) {\n"
            "  const p = path.resolve(req.query.path);\n"
            "  return fs.readFileSync(p);\n"
            "}\n"
        )
        findings = _scan_lang(
            tmp_path, "javascript_taint.yaml", src, "tnt-js-path-001",
            language="javascript", filename="test.js",
        )
        assert findings, "path.resolve(...) must not suppress tnt-js-path-001"


class TestAllowlistMembershipSanitizerFix:
    """DEF-40 (BACKLOG.md) -- TNT-AIML-001's `$PATH in $ALLOWED_MODELS` and
    TNT-SSRF-001's `$URL in $ALLOWLIST` were listed as "confirmed sound" in
    docs/taint-sanitizer-audit.md, but rules/agent_taint.yaml's header
    (written later) flagged them as very likely non-functional: a bare
    `pattern-sanitizers` entry matching a boolean membership test is a
    disconnected expression node that never intercepts the tainted value,
    so it doesn't clear taint the way a reassignment/wrap (`$X =
    validate($X)`) does.

    Re-verified empirically 2026-07-13: with the *old* pattern-sanitizers
    approach, the finding fired in every guard-clause shape tested,
    including both correctly-guarded ones -- confirming agent_taint.yaml's
    header was right and the audit doc's verdict was wrong. Fixed by
    replacing the non-functional `pattern-sanitizers` with a sink-level
    `pattern-not-inside` structural exclusion (syntactic containment, not
    dataflow), which these tests confirm actually suppresses the guarded
    cases while still firing on the unguarded one. The early-return idiom
    (`if x not in ALLOWLIST: return` followed by the sink at the same
    indentation level, no `else`) is a documented, accepted residual gap:
    it is not a containment relationship, so it is not recognized and still
    produces a finding (over-flagging, not a silent false negative).
    """

    def test_unsanitized_still_fires_aiml(self, tmp_path):
        src = (
            "from flask import request\n"
            "from transformers import AutoModel\n"
            "\n"
            "def handler():\n"
            "    path = request.args.get('model_path')\n"
            "    return AutoModel.from_pretrained(path, trust_remote_code=True)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-AIML-001")
        assert findings, "unguarded model path must still be flagged by TNT-AIML-001"

    def test_positive_branch_guard_suppresses_aiml(self, tmp_path):
        """if path in ALLOWED_MODELS: <use path> -- the sink is lexically
        inside the guarded branch; must be suppressed."""
        src = (
            "from flask import request\n"
            "from transformers import AutoModel\n"
            "\n"
            "ALLOWED_MODELS = ['bert-base-uncased', 'gpt2']\n"
            "\n"
            "def handler():\n"
            "    path = request.args.get('model_path')\n"
            "    if path in ALLOWED_MODELS:\n"
            "        return AutoModel.from_pretrained(path, trust_remote_code=True)\n"
            "    return 'invalid', 400\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-AIML-001")
        assert not findings, "path in ALLOWED_MODELS guard must suppress TNT-AIML-001"

    def test_if_else_branch_guard_suppresses_aiml(self, tmp_path):
        """if path not in ALLOWED_MODELS: return ... else: <use path> --
        the sink is lexically inside the else branch; must be suppressed."""
        src = (
            "from flask import request\n"
            "from transformers import AutoModel\n"
            "\n"
            "ALLOWED_MODELS = ['bert-base-uncased', 'gpt2']\n"
            "\n"
            "def handler():\n"
            "    path = request.args.get('model_path')\n"
            "    if path not in ALLOWED_MODELS:\n"
            "        return 'invalid', 400\n"
            "    else:\n"
            "        return AutoModel.from_pretrained(path, trust_remote_code=True)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-AIML-001")
        assert not findings, "if/else ALLOWED_MODELS guard must suppress TNT-AIML-001"

    def test_early_return_guard_is_a_known_residual_gap_aiml(self, tmp_path):
        """if path not in ALLOWED_MODELS: return (no else, sink follows at
        the same indentation level) is NOT a containment relationship, so
        pattern-not-inside cannot recognize it -- documented residual gap,
        still produces a finding even though the code is actually safe."""
        src = (
            "from flask import request\n"
            "from transformers import AutoModel\n"
            "\n"
            "ALLOWED_MODELS = ['bert-base-uncased', 'gpt2']\n"
            "\n"
            "def handler():\n"
            "    path = request.args.get('model_path')\n"
            "    if path not in ALLOWED_MODELS:\n"
            "        return 'invalid', 400\n"
            "    return AutoModel.from_pretrained(path, trust_remote_code=True)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-AIML-001")
        assert findings, (
            "documented residual gap: early-return guard is not recognized, "
            "so this still fires (over-flagging, not a silent false negative)"
        )

    def test_unsanitized_still_fires_ssrf(self, tmp_path):
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    return requests.get(url)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "unguarded URL must still be flagged by TNT-SSRF-001"

    def test_positive_branch_guard_suppresses_ssrf(self, tmp_path):
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if url in ALLOWLIST:\n"
            "        return requests.get(url)\n"
            "    return 'invalid', 400\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert not findings, "url in ALLOWLIST guard must suppress TNT-SSRF-001"

    def test_if_else_branch_guard_suppresses_ssrf(self, tmp_path):
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if url not in ALLOWLIST:\n"
            "        return 'invalid', 400\n"
            "    else:\n"
            "        return requests.get(url)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert not findings, "if/else ALLOWLIST guard must suppress TNT-SSRF-001"

    def test_early_return_guard_is_a_known_residual_gap_ssrf(self, tmp_path):
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if url not in ALLOWLIST:\n"
            "        return 'invalid', 400\n"
            "    return requests.get(url)\n"
        )
        findings = _scan(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, (
            "documented residual gap: early-return guard is not recognized, "
            "so this still fires (over-flagging, not a silent false negative)"
        )


class TestGuardClausePostFilter:
    """GitHub issue #160 -- closes the early-return residual gap documented
    just above (and in docs/taint-sanitizer-audit.md's DEF-40 correction)
    with an AST post-filter in EnrichmentPass, run after Opengrep rather
    than expressed as an Opengrep rule. Opengrep itself still can't
    recognize the early-return idiom (the tests above still assert the raw
    `_scan()` finding fires), so these use `_scan_and_enrich()` to verify
    the finding survives (never deleted) but is downgraded to confidence
    <= 0.3 with `metadata["guard_suppressed"]` set once EnrichmentPass runs.

    The five negative cases mirror the issue's precision requirements
    exactly: guard on a different variable, guard whose body doesn't
    unconditionally exit, guard positioned after the sink, re-taint between
    guard and sink, and a guard inside a loop whose sink sits outside it --
    each must leave `metadata["guard_suppressed"]` unset (i.e. this
    post-filter must not have fired). Note: these end-to-end findings can
    still be downgraded to low confidence by an unrelated, pre-existing
    enrichment step (`_apply_source_confidence`'s AST source-origin
    resolution mis-classifies a bare `request.args.get(...)` snippet as
    `function_param` rather than `http_input` -- out of scope for issue
    #160), so confidence is not asserted here; the precise "does the
    guard-clause detector itself return a match" behavior for each of these
    five shapes is covered directly, independent of that confound, in
    `tests/test_guard_clause.py`.
    """

    def test_early_return_guard_now_suppressed_ssrf(self, tmp_path):
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if url not in ALLOWLIST:\n"
            "        return 'invalid', 400\n"
            "    return requests.get(url)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "guard-clause post-filter must downgrade, not delete, the finding"
        assert findings[0].confidence <= 0.3, (
            f"early-return guard must downgrade confidence to <= 0.3, got {findings[0].confidence}"
        )
        assert findings[0].metadata.get("guard_suppressed") == "membership"

    def test_early_return_guard_now_suppressed_aiml(self, tmp_path):
        src = (
            "from flask import request\n"
            "from transformers import AutoModel\n"
            "\n"
            "ALLOWED_MODELS = ['bert-base-uncased', 'gpt2']\n"
            "\n"
            "def handler():\n"
            "    path = request.args.get('model_path')\n"
            "    if path not in ALLOWED_MODELS:\n"
            "        return 'invalid', 400\n"
            "    return AutoModel.from_pretrained(path, trust_remote_code=True)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-AIML-001")
        assert findings, "guard-clause post-filter must downgrade, not delete, the finding"
        assert findings[0].confidence <= 0.3, (
            f"early-return guard must downgrade confidence to <= 0.3, got {findings[0].confidence}"
        )
        assert findings[0].metadata.get("guard_suppressed") == "membership"

    def test_prefix_guard_now_suppressed_ssrf(self, tmp_path):
        """`not url.startswith(ALLOWED_PREFIX)` -- the prefix guard shape,
        pinned to an ALL_CAPS name per the issue (an unbound `.startswith()`
        alone was rejected as a sanitizer in issue #87; this differs because
        the guarded branch must also unconditionally exit)."""
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWED_PREFIX = 'https://api.example.com/'\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if not url.startswith(ALLOWED_PREFIX):\n"
            "        return 'invalid', 400\n"
            "    return requests.get(url)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "guard-clause post-filter must downgrade, not delete, the finding"
        assert findings[0].confidence <= 0.3
        assert findings[0].metadata.get("guard_suppressed") == "prefix"

    def test_guard_on_different_variable_does_not_suppress(self, tmp_path):
        """A guard testing an unrelated variable must not suppress the
        finding for the actually-tainted one."""
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    other = request.args.get('other')\n"
            "    if other not in ALLOWLIST:\n"
            "        return 'invalid', 400\n"
            "    return requests.get(url)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "unguarded url must still be flagged"
        assert "guard_suppressed" not in findings[0].metadata, (
            "guard on a different variable ('other') must not suppress the "
            "finding for 'url'"
        )

    def test_guard_body_that_does_not_exit_does_not_suppress(self, tmp_path):
        """A guard whose body logs and falls through (no return/raise/exit)
        must not suppress -- it never actually gates control flow."""
        src = (
            "import logging\n"
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if url not in ALLOWLIST:\n"
            "        logging.warning('blocked url: %s', url)\n"
            "    return requests.get(url)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "unguarded url must still be flagged"
        assert "guard_suppressed" not in findings[0].metadata, (
            "a guard body that only logs and falls through must not suppress"
        )

    def test_guard_after_sink_does_not_suppress(self, tmp_path):
        """A guard positioned after the sink in execution order must not
        suppress -- it can't have gated the call that already happened."""
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    result = requests.get(url)\n"
            "    if url not in ALLOWLIST:\n"
            "        return 'invalid', 400\n"
            "    return result\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "unguarded url must still be flagged"
        assert "guard_suppressed" not in findings[0].metadata, (
            "a guard appearing after the sink must not suppress"
        )

    def test_retaint_after_guard_does_not_suppress(self, tmp_path):
        """Reassigning the tainted variable from a fresh source expression
        between the guard and the sink must not suppress -- the guard only
        validated the earlier value, not the one that actually reaches the
        sink."""
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    if url not in ALLOWLIST:\n"
            "        return 'invalid', 400\n"
            "    url = request.args.get('url2')\n"
            "    return requests.get(url)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "unguarded (re-tainted) url must still be flagged"
        assert "guard_suppressed" not in findings[0].metadata, (
            "re-taint between guard and sink must not suppress"
        )

    def test_guard_inside_loop_with_sink_outside_does_not_suppress(self, tmp_path):
        """A guard living inside a loop body does not dominate a sink that
        sits after the loop -- the loop may run zero iterations, so the
        guard is never guaranteed to have executed."""
        src = (
            "import requests\n"
            "from flask import request\n"
            "\n"
            "ALLOWLIST = ['https://api.example.com']\n"
            "\n"
            "def handler():\n"
            "    url = request.args.get('url')\n"
            "    for _ in range(3):\n"
            "        if url not in ALLOWLIST:\n"
            "            return 'invalid', 400\n"
            "    return requests.get(url)\n"
        )
        findings = _scan_and_enrich(tmp_path, "ai_ml_taint.yaml", src, "TNT-SSRF-001")
        assert findings, "unguarded url must still be flagged"
        assert "guard_suppressed" not in findings[0].metadata, (
            "a guard inside a loop body must not suppress a sink outside the loop"
        )


class TestGuardrailIdentifierSanitizerFix:
    """`TNT-AIML-004`'s prompt-injection sanitizers (issue #186).

    These four entries (`moderation`, `content_filter`, `prompt_guard`,
    `LlamaGuard`) were bare identifiers. `docs/taint-sanitizer-audit.md`'s
    #84/#87 pass left them in place, reasoning they were inert best-effort
    signals rather than unsound guards. They were not inert -- they were
    backwards, in both directions:

      * a tainted value merely BOUND TO a variable of one of those names had
        its taint cleared, suppressing a genuine finding; and
      * an actual call to a guardrail function did not clear taint at all.

    Requiring a call shape fixes both. Each test below reproduces one
    direction against the live rule.
    """

    _SINK = "agent.run"

    def _src(self, body: str) -> str:
        return (
            "from flask import request\n"
            "agent = object()\n"
            "\n"
            "def handler():\n"
            f"{body}"
        )

    def test_variable_named_moderation_no_longer_clears_taint(self, tmp_path):
        """The core false negative: nothing is sanitized here at all, the
        tainted value simply happens to be named `moderation`."""
        src = self._src(
            "    moderation = request.args.get('q')\n"
            "    agent.run(moderation)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert findings, (
            "a tainted value must not be sanitized by its variable NAME; "
            "no guardrail is called in this source at all"
        )

    def test_variable_named_content_filter_no_longer_clears_taint(self, tmp_path):
        src = self._src(
            "    content_filter = request.args.get('q')\n"
            "    agent.run(content_filter)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert findings, "name collision on `content_filter` must not clear taint"

    def test_variable_named_llamaguard_no_longer_clears_taint(self, tmp_path):
        src = self._src(
            "    LlamaGuard = request.args.get('q')\n"
            "    agent.run(LlamaGuard)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert findings, "name collision on `LlamaGuard` must not clear taint"

    def test_control_unrelated_name_still_fires(self, tmp_path):
        """Control for the three tests above: identical shape, ordinary
        variable name. Proves those cases differ only by the name."""
        src = self._src(
            "    plain = request.args.get('q')\n"
            "    agent.run(plain)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert findings, "unguarded prompt injection must fire"

    def test_guardrail_call_now_suppresses(self, tmp_path):
        """The other direction: a real transform through a guardrail
        function used to be reported anyway."""
        src = (
            "from flask import request\n"
            "agent = object()\n"
            "\n"
            "def moderation(text):\n"
            "    return text\n"
            "\n"
            "def handler():\n"
            "    q = request.args.get('q')\n"
            "    q = moderation(q)\n"
            "    agent.run(q)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert not findings, (
            "a value passed THROUGH a guardrail call must clear taint"
        )

    def test_method_form_guardrail_call_suppresses(self, tmp_path):
        src = (
            "from flask import request\n"
            "agent = object()\n"
            "guard = object()\n"
            "\n"
            "def handler():\n"
            "    q = request.args.get('q')\n"
            "    q = guard.sanitize(q)\n"
            "    agent.run(q)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert not findings, "`guard.sanitize(q)` is a genuine transform"

    def test_verdict_call_does_not_suppress(self, tmp_path):
        """`client.moderations.create(...)` returns a judgement and does not
        transform the value, so it must NOT clear taint. Enforcement of such
        a verdict is a control-flow property (ns-aiml-156/131/132), not a
        dataflow one."""
        src = (
            "from flask import request\n"
            "import openai\n"
            "client = openai.OpenAI()\n"
            "agent = object()\n"
            "\n"
            "def handler():\n"
            "    q = request.args.get('q')\n"
            "    client.moderations.create(input=q)\n"
            "    agent.run(q)\n"
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-AIML-004")
        assert findings, (
            "a discarded moderation verdict must not clear taint"
        )


class TestSqli002TextWrapper:
    """TNT-SQLI-002 (BACKLOG RT-05): `text(...)` is SQLAlchemy's raw-SQL
    constructor, not a sanitizer."""

    def test_text_wrapped_concatenation_still_fires(self, tmp_path):
        src = (
            "from flask import request\n"
            "from sqlalchemy import text\n\n"
            "def q(db):\n"
            "    uid = request.args.get('id')\n"
            '    db.execute(text("SELECT * FROM users WHERE id = " + uid))\n'
        )
        findings = _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-SQLI-002")
        assert [f.start_line for f in findings] == [6]

    def test_bound_parameters_still_do_not_fire(self, tmp_path):
        src = (
            "from flask import request\n"
            "from sqlalchemy import text\n\n"
            "def q(db):\n"
            "    uid = request.args.get('id')\n"
            '    db.execute(text("SELECT * FROM users WHERE id = :id"), {"id": uid})\n'
        )
        assert _scan(tmp_path, "python_taint_extended.yaml", src, "TNT-SQLI-002") == []

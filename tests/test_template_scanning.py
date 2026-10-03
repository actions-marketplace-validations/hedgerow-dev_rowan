"""Template scanning (#268): .html/.jinja files reach the scanner at all, the
template rules fire on real escaping bypasses, and Django's HTTP sources are
no longer misclassified as function parameters.

Before this, template files were never opened: on the RealVuln corpus Rowan
produced zero findings in any .html file while ~60 labelled vulnerabilities
lived in them.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from rowan.analysis.source_tracer import classify_origin
from rowan.config import ScanConfig
from rowan.passes.file_scan import LANGUAGE_EXTENSIONS
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

_TEMPLATE = """\
<div>
  {% autoescape false %}
    {{ comment_body }}
  {% endautoescape %}
  <p>{{ bio|safe }}</p>
  <span>{{ name }}</span>
  <span>{{ other|escape }}</span>
</div>
"""

_DJANGO_VIEW = '''\
from django.utils.safestring import mark_safe
from django.utils.html import format_html, escape


def profile(request):
    bio = request.GET.get("bio")
    return mark_safe(bio)


def safe_profile(request):
    bio = request.GET.get("bio")
    return mark_safe(escape(bio))


def safe_args(request):
    name = request.GET.get("name")
    return format_html("<b>{}</b>", name)
'''


def _scan(tmp_path: Path):
    (tmp_path / "templates").mkdir()
    (tmp_path / "templates" / "vuln.html").write_text(_TEMPLATE, encoding="utf-8")
    (tmp_path / "views.py").write_text(_DJANGO_VIEW, encoding="utf-8")
    return ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()


def test_template_extensions_registered() -> None:
    """The maps that decide which files are opened must agree, or a file
    reaches one engine and not the other."""
    assert ".html" in LANGUAGE_EXTENSIONS["html"]
    assert ".jinja2" in LANGUAGE_EXTENSIONS["html"]
    assert ".html" in OpengrepAdapter._LANG_EXTENSIONS["html"]
    assert set(LANGUAGE_EXTENSIONS["html"]) == set(OpengrepAdapter._LANG_EXTENSIONS["html"])


def test_template_files_are_scanned_and_rules_fire(tmp_path: Path) -> None:
    result = _scan(tmp_path)

    by_rule = {f.rule_id: f for f in result.findings}
    assert "NS-TPL-001" in by_rule, "autoescape false must be flagged"
    assert "NS-TPL-002" in by_rule, "|safe must be flagged"

    # The |safe finding must land on the |safe line, not the plain {{ name }}
    # or the explicitly-escaped {{ other|escape }}.
    assert by_rule["NS-TPL-002"].start_line == 5
    tpl_findings = [f for f in result.findings if f.file_path.endswith(".html")]
    assert len(tpl_findings) == 2, [
        (f.rule_id, f.start_line) for f in tpl_findings
    ]


def test_template_rules_survive_the_web_context_gate(tmp_path: Path) -> None:
    """A template has no Python web imports, so the web-context gate would
    floor every template finding to INFO if it did not exempt templates."""
    result = _scan(tmp_path)
    tpl = [f for f in result.findings if f.file_path.endswith(".html")]
    assert tpl
    for f in tpl:
        assert not f.metadata.get("web_context_gate"), f.rule_id
        assert f.severity.value != "info", f"{f.rule_id} was floored to INFO"


def test_django_mark_safe_taint(tmp_path: Path) -> None:
    result = _scan(tmp_path)
    xss = [f for f in result.findings if f.rule_id == "TNT-XSS-002"]
    assert len(xss) == 1, [(f.rule_id, f.start_line) for f in result.findings]
    finding = xss[0]
    # It must carry real evidence, not be a pattern guess.
    assert finding.taint_flow is not None
    assert finding.metadata["evidence_tier"] == "taint-flow"
    # And it must land on the unsanitized view, not the escape()d one or the
    # format_html() call whose arguments are escaped by the framework.
    assert finding.start_line == 7


def test_django_request_is_http_input_not_function_param(tmp_path: Path) -> None:
    """Django views take `request` as a parameter, so tracing the root
    variable back finds no assignment and used to yield function_param (0.3)
    -- under every threshold in _SAFE_ORIGINS_BY_CATEGORY, which floored the
    finding to INFO. The snippet is itself the origin expression."""
    view = tmp_path / "views.py"
    view.write_text(_DJANGO_VIEW, encoding="utf-8")

    assert classify_origin(str(view), 'request.GET.get("bio")', 6) == ("http_input", 1.0)
    assert classify_origin(str(view), 'request.POST["x"]', 6) == ("http_input", 1.0)
    # Flask's shape must keep working too.
    assert classify_origin(str(view), 'request.args.get("q")', 6) == ("http_input", 1.0)
    # Non-HTTP origins keep their own classification.
    assert classify_origin(str(view), 'os.environ.get("HOME")', 6) == ("env_variable", 0.7)
    # A bare name carries no information and must still fall back to tracing.
    assert classify_origin(str(view), "x", 6) == ("function_param", 0.3)


_FLASK_APP = '''\
import os
import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    return requests.get(url).text


@app.route("/ping")
def ping():
    host = request.args.get("host")
    return os.system("ping -c 1 " + host)
'''


def test_flask_request_source_is_not_floored_to_info(tmp_path: Path) -> None:
    """Regression: canonical Flask SSRF was reported at INFO/0.15.

    `from flask import request` is an import, not an assignment, so the
    root-variable trace found nothing and returned function_param (0.3).
    That is below the SSRF threshold (0.5) and the 0.7 default, so
    _apply_source_confidence floored SSRF, XSS and command-injection
    confidence for every request-sourced flow -- meaning the documented
    `scan --severity high` CI gate passed textbook Flask SSRF.
    Deserialization and path traversal escaped only because their
    thresholds (0.1/0.3) happen to sit at or below 0.3.
    """
    (tmp_path / "app.py").write_text(_FLASK_APP, encoding="utf-8")
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()

    flowed = [f for f in result.findings if f.taint_flow is not None]
    assert flowed, "the Flask app must produce taint findings"

    for f in flowed:
        assert f.metadata.get("source_origin") == "http_input", (
            f"{f.rule_id} classified its request source as "
            f"{f.metadata.get('source_origin')}"
        )
        assert not f.metadata.get("taint_unconfirmed"), f"{f.rule_id} was floored"

    ssrf = [f for f in flowed if f.category.value == "ssrf"]
    assert ssrf, "requests.get(user_url) must be reported as SSRF"
    assert all(f.severity.value != "info" for f in ssrf), (
        "Flask SSRF must not be INFO -- that is what let --severity high pass it"
    )


def test_html_reported_as_patterns_only(tmp_path: Path) -> None:
    """There is no template dataflow engine, so a scan must say so rather
    than let a quiet .html result read as a clean one."""
    result = _scan(tmp_path)
    capability = result.metadata["analysis_capability"]
    assert capability["patterns_only_languages"].get("html") == 1
    assert "html" not in capability["dataflow_languages"]


def test_inert_html_is_not_flagged(tmp_path: Path) -> None:
    """Plain HTML with no template constructs must produce nothing -- the
    rules key on engine syntax, not on the file being HTML."""
    (tmp_path / "static.html").write_text(
        textwrap.dedent(
            """\
            <html><body>
              <h1>Hello</h1>
              <p>Some text with {braces} and a | pipe character.</p>
            </body></html>
            """
        ),
        encoding="utf-8",
    )
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True)).run()
    assert [f for f in result.findings if f.file_path.endswith(".html")] == []

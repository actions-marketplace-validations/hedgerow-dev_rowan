"""Regression tests: Django request sources reach the Python taint sinks.

The Python taint rules historically inlined a Flask-only source list
(`request.args.get`, `request.form.get`, `request.json.get`), so a textbook
Django flow such as pygoat's `request.POST.get('domain')` ->
`subprocess.Popen(cmd, shell=True)` produced zero findings. Those rules now
expand the shared registry fragment (`rowan.rules_registry`), which
includes `request.POST`/`request.GET`; these tests pin that widening.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, rule_file, source, rule_id, language):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [RULES_DIR / rule_file], languages=[language])
    return [f for f in findings if f.rule_id == rule_id]


_CASES = [
    (
        "TNT-CMDI-001",
        "python_taint_extended.yaml",
        "import subprocess\n\n"
        "def view(request):\n"
        "    domain = request.POST.get('domain')\n"
        '    command = "dig {}".format(domain)\n'
        "    return subprocess.Popen(command, shell=True)\n",
    ),
    (
        "TNT-SSRF-002",
        "python_taint_extended.yaml",
        "import requests\n\n"
        "def view(request):\n"
        "    url = request.POST.get('url')\n"
        "    return requests.get(url)\n",
    ),
    (
        "TNT-PATH-002",
        "python_taint_extended.yaml",
        "def view(request):\n"
        "    name = request.POST.get('name')\n"
        "    return open(name).read()\n",
    ),
    (
        "TNT-XSS-001",
        "web_taint.yaml",
        "from django.http import HttpResponse\n\n"
        "def view(request):\n"
        "    name = request.POST.get('name')\n"
        "    return HttpResponse(name)\n",
    ),
]


@pytest.mark.parametrize(("rule_id", "rule_file", "source"), _CASES, ids=[c[0] for c in _CASES])
def test_django_post_reaches_sink(tmp_path, rule_id, rule_file, source):
    findings = _scan(tmp_path, "views.py", rule_file, source, rule_id, "python")
    assert len(findings) == 1, [f.rule_id for f in findings]


_DJANGO_RENDER = (
    "from django.shortcuts import render\n\n"
    "def view(request):\n"
    "    q = request.GET.get('q')\n"
    "    return render(request, 'search.html', {'q': q})\n"
)


@pytest.mark.parametrize(
    ("rule_id", "rule_file"),
    [("TNT-SSTI-001", "ai_ml_taint.yaml"), ("TNT-SSTI-003", "python_taint_extended.yaml")],
)
def test_django_render_shortcut_is_not_ssti(tmp_path, rule_id, rule_file):
    """`render(request, "literal.html", ctx)` resolves to django.shortcuts.render
    and used to match the `$TEMPLATE.render(...)` sink; the template is a literal
    file name and the tainted value is autoescaped context."""
    findings = _scan(tmp_path, "views.py", rule_file, _DJANGO_RENDER, rule_id, "python")
    assert findings == []

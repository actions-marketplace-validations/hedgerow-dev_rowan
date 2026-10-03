"""Generalization fixtures for TNT-UPLOAD-001 (rules/web_taint.yaml): untrusted
uploaded content written to disk (CWE-434).

The point of this rule is that it detects the *semantic* pattern -- an uploaded
file object or raw request body reaching a filesystem-write sink -- across every
mainstream Python web framework, not one memorized idiom. Each vulnerable
fixture below uses a DIFFERENT framework and code shape (Flask .save, Flask raw
open().write, Django default_storage, FastAPI UploadFile + copyfileobj,
Starlette raw body, Tornado self.request.files). If the rule only fired on one
of them it would be benchmark-fitting, not detection.

Requires the Opengrep binary (skipped if not installed, matching the project's
convention -- CI does not install it).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "web_taint.yaml"
RULE_ID = "TNT-UPLOAD-001"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source):
    (tmp_path / filename).write_text(source, encoding="utf-8")
    findings = OpengrepAdapter().scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == RULE_ID]


# --- vulnerable: same vuln, six frameworks/idioms; every one must fire --------

VULN = {
    "flask_save": (
        "from flask import request\n"
        "def upload():\n"
        "    f = request.files['doc']\n"
        "    f.save('/var/www/uploads/' + f.filename)\n"
    ),
    "flask_rawwrite": (
        "from flask import request\n"
        "def upload():\n"
        "    data = request.files['doc'].read()\n"
        "    with open('/var/www/uploads/x.dat', 'wb') as out:\n"
        "        out.write(data)\n"
    ),
    "django_storage": (
        "from django.core.files.storage import default_storage\n"
        "def upload(request):\n"
        "    up = request.FILES['doc']\n"
        "    default_storage.save('media/' + up.name, up)\n"
    ),
    "fastapi_uploadfile": (
        "from fastapi import UploadFile\n"
        "import shutil\n"
        "async def upload(file: UploadFile):\n"
        "    with open('/srv/uploads/' + file.filename, 'wb') as buffer:\n"
        "        shutil.copyfileobj(file.file, buffer)\n"
    ),
    "starlette_body": (
        "from pathlib import Path\n"
        "async def upload(request):\n"
        "    body = await request.body()\n"
        "    Path('/srv/incoming/blob.bin').write_bytes(body)\n"
    ),
    "tornado_handler": (
        "import tornado.web\n"
        "class UploadHandler(tornado.web.RequestHandler):\n"
        "    def post(self):\n"
        "        file1 = self.request.files['file1'][0]\n"
        "        out = open('/tmp/' + 'x', 'wb')\n"
        "        out.write(file1['body'])\n"
    ),
}


@pytest.mark.parametrize("name,source", list(VULN.items()))
def test_upload_vuln_fires_across_frameworks(tmp_path, name, source):
    findings = _scan(tmp_path, f"{name}.py", source)
    assert findings, f"{name}: untrusted upload -> disk write must fire TNT-UPLOAD-001"


# --- safe: no untrusted source, or a genuine content gate; must NOT fire ------

SAFE = {
    "static_write": (
        "def log_event(msg):\n"
        "    with open('/var/log/app.log', 'a') as f:\n"
        "        f.write('event occurred\\n')\n"
    ),
    "constant_bytes": (
        "from pathlib import Path\n"
        "def dump_defaults():\n"
        "    Path('/etc/app/defaults.json').write_bytes(b'{\"k\": 1}')\n"
    ),
    "content_validated": (
        "from flask import request\n"
        "import magic\n"
        "def upload():\n"
        "    data = request.files['doc'].read()\n"
        "    if magic.from_buffer(data, mime=True) not in ('image/png',):\n"
        "        return 'no'\n"
        "    checked = magic.from_buffer(data)\n"
        "    open('/srv/up/x.png', 'wb').write(checked)\n"
    ),
}


@pytest.mark.parametrize("name,source", list(SAFE.items()))
def test_upload_safe_does_not_fire(tmp_path, name, source):
    findings = _scan(tmp_path, f"{name}.py", source)
    assert findings == [], f"{name}: no untrusted upload flow -> must not fire ({findings})"

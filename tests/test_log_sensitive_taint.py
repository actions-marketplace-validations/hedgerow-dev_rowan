"""Generalization fixtures for TNT-LOG-002 (rules/web_taint.yaml): a sensitive
value (credential, auth/API-key header, session cookie, raw request body, or a
secret-named request field) written to a log sink -- CWE-532.

Distinct from TNT-LOG-001 (CWE-117 log forging). Because it is a taint rule, a
value masked/redacted/hashed before logging clears taint and must NOT fire --
something the retired presence rule ns-log-002 could not see. Each vulnerable
fixture uses a DIFFERENT framework/idiom; if it only fired on one, that would be
benchmark-fitting, not detection.

Requires the Opengrep binary (skipped if not installed).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "web_taint.yaml"
RULE_ID = "TNT-LOG-002"

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


VULN = {
    "flask_body_and_authheader": (
        "import logging\n"
        "from flask import request\n"
        "logger = logging.getLogger(__name__)\n"
        "def intake():\n"
        "    payload = request.get_data(as_text=True)\n"
        "    logger.warning('intake payload=%s auth=%s', payload, request.headers.get('Authorization'))\n"
    ),
    "django_password_field": (
        "import logging\n"
        "logger = logging.getLogger('auth')\n"
        "def login_view(request):\n"
        "    password = request.POST.get('password')\n"
        "    logger.info('login {} / {}'.format(request.POST.get('username'), password))\n"
    ),
    "fastapi_cookie_and_body": (
        "import logging\n"
        "from fastapi import Request\n"
        "log = logging.getLogger('api')\n"
        "async def session(request: Request):\n"
        "    raw = await request.body()\n"
        "    token = request.cookies.get('session_token')\n"
        "    log.debug(f'new session raw={raw} token={token}')\n"
    ),
    "aiohttp_auth_header_print": (
        "import logging\n"
        "logger = logging.getLogger('svc')\n"
        "async def handle(request):\n"
        "    auth = request.headers.get('Authorization')\n"
        "    print('debug auth:', auth)\n"
    ),
    "tornado_env_secret": (
        "import logging, os\n"
        "import tornado.web\n"
        "class KeyHandler(tornado.web.RequestHandler):\n"
        "    def get(self):\n"
        "        api_key = os.environ['SERVICE_API_KEY']\n"
        "        logging.getLogger('a').info('using api_key=%s', api_key)\n"
    ),
    "bottle_client_secret_field": (
        "import logging\n"
        "from bottle import request\n"
        "def oauth():\n"
        "    client_secret = request.forms.get('client_secret')\n"
        "    logging.debug('exchange client_secret=' + client_secret)\n"
    ),
}


@pytest.mark.parametrize("name,source", list(VULN.items()))
def test_sensitive_log_fires_across_frameworks(tmp_path, name, source):
    assert _scan(tmp_path, f"{name}.py", source), (
        f"{name}: sensitive value -> log sink must fire TNT-LOG-002"
    )


SAFE = {
    # masked / redacted / hashed before logging -> sanitizer clears taint
    "masked": (
        "import logging\n"
        "from flask import request\n"
        "def mask(v):\n"
        "    return (v[:4] + '***') if v else v\n"
        "def intake():\n"
        "    logging.warning('auth=%s', mask(request.headers.get('Authorization')))\n"
    ),
    "hashed": (
        "import logging, hashlib\n"
        "def record(password):\n"
        "    logging.info('pw digest=%s', hashlib.sha256(password.encode()).hexdigest())\n"
    ),
    # non-sensitive request params (page / user_id) are not CWE-532
    "nonsensitive_params": (
        "import logging\n"
        "from flask import request\n"
        "def audit():\n"
        "    logging.info('page=%s user=%s', request.args.get('page'), request.args.get('user_id'))\n"
    ),
    # token COUNTS, not credentials (the rowan/agents/llm_backend.py FP)
    "token_counts": (
        "import logging\n"
        "def report(usage, max_tokens):\n"
        "    reasoning_tokens = usage.get('reasoning_tokens')\n"
        "    logging.warning('used %d of %d, %s reasoning', 0, max_tokens, reasoning_tokens)\n"
    ),
}


@pytest.mark.parametrize("name,source", list(SAFE.items()))
def test_safe_log_does_not_fire(tmp_path, name, source):
    findings = _scan(tmp_path, f"{name}.py", source)
    assert findings == [], f"{name}: must not fire TNT-LOG-002 ({findings})"

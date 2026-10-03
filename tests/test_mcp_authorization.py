"""MCP OAuth 2.1 authorization surface (issue #187, epic #183).

`ns-aiml-125..128` already cover tool-description poisoning, `0.0.0.0` binds,
network transport selection, and unreviewed sampling approval. `NS-AIML-009`/
`012` cover unauthenticated tool exposure and stdio-outside-dev. `TNT-ML-024`/
`025` (Opengrep taint, tested in test_mcp_tool_poisoning_confused_deputy.py)
cover tool-registration poisoning ("rug pull") and the direct
parameter-to-upstream-header confused-deputy shape.

This file covers what none of the above reads: the MCP authorization spec's
own OAuth 2.1 layer.

  ns-aiml-159  missing audience (`aud`) validation on a decoded/verified token
  ns-aiml-160  redirect URI validated by prefix, or DCR-registered unvalidated
  ns-aiml-161  MCP session id used as authentication, or generated predictably
  ns-aiml-162  wildcard resource indicator / client-supplied AS URL / no PKCE

References: RFC 8707 (Resource Indicators for OAuth 2.0), RFC 7591 (Dynamic
Client Registration), RFC 7636 (PKCE), OAuth 2.0 Security Best Current
Practice, and the MCP authorization specification.

Item 2 from the issue (token passthrough via a session/context store written
in one function and read in another) needs a cross-file taint channel --
verified empirically that Opengrep's own interprocedural taint does not
follow a `self.attr = param` / `self.attr` read-back across methods within a
single file, so this is not a rule this file can express. Filed separately
(see the epic tracking) as a `CrossFilePass` channel, following the same
write-recognizer/read-recognizer/armed-channel shape already used for the
ORM and vector-store second-order channels there.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.core.rules import load_neuroscan_rules
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_PATH = Path(__file__).parent.parent / "rules" / "ai_security.yaml"
CONVERTED_RULES_PATH = Path(__file__).parent.parent / "rules" / "converted" / "ai_security.yaml"
_RULES = load_neuroscan_rules(RULES_PATH)

_adapter = OpengrepAdapter()
_needs_opengrep = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    """LEGACY engine (`ScanConfig.legacy_neuroscan=True`): NeuroScan's own
    per-line matcher with the windowed `sanitizers:` field."""
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _scan_converted(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    """CONVERTED engine (`ScanConfig.legacy_neuroscan=False`, the DEFAULT):
    the same rule compiled to Opengrep `pattern-regex`/`pattern-not-regex`
    and run through the real Opengrep binary. See
    TestConvertedEngineDefaultParity below for why this is a separate,
    necessary check rather than redundant with `_scan`."""
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [CONVERTED_RULES_PATH], languages=["python", "javascript", "typescript"])
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


class TestNsAiml133AudienceValidation:
    """Item 1: a decoded/verified token with no `aud` check nearby."""

    def test_pyjwt_no_audience_flagged(self, tmp_path):
        src = (
            "import jwt\n\n"
            "def handle_request(token):\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])\n"
            "    return payload\n"
        )
        assert _scan(tmp_path, "server.py", src, "ns-aiml-159")

    def test_ts_jsonwebtoken_no_audience_flagged(self, tmp_path):
        src = (
            'import jwt from "jsonwebtoken";\n\n'
            "function handleRequest(token: string) {\n"
            '  const payload = jwt.verify(token, publicKey, { algorithms: ["RS256"] });\n'
            "  return payload;\n"
            "}\n"
        )
        assert _scan(tmp_path, "server.ts", src, "ns-aiml-159")

    def test_ts_jose_no_audience_flagged(self, tmp_path):
        src = (
            'import { jwtVerify } from "jose";\n\n'
            "async function handleRequest(token: string) {\n"
            "  const { payload } = await jwtVerify(token, JWKS);\n"
            "  return payload;\n"
            "}\n"
        )
        assert _scan(tmp_path, "server.ts", src, "ns-aiml-159")

    def test_pyjwt_with_audience_kwarg_not_flagged(self, tmp_path):
        """The TN this rule's shippability depends on: the server that
        decodes the JWT and asserts the audience via the library's own
        parameter."""
        src = (
            "import jwt\n\n"
            "def handle_request(token):\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'], audience=RESOURCE_ID)\n"
            "    return payload\n"
        )
        assert not _scan(tmp_path, "server.py", src, "ns-aiml-159")

    def test_ts_with_audience_option_not_flagged(self, tmp_path):
        src = (
            'import jwt from "jsonwebtoken";\n\n'
            "function handleRequest(token: string) {\n"
            "  const payload = jwt.verify(token, publicKey, { algorithms: [\"RS256\"], audience: resourceId });\n"
            "  return payload;\n"
            "}\n"
        )
        assert not _scan(tmp_path, "server.ts", src, "ns-aiml-159")

    def test_manual_aud_comparison_not_flagged(self, tmp_path):
        """A manual `payload['aud'] != RESOURCE_ID` check after decode is a
        valid form of audience validation, not merely a library kwarg."""
        src = (
            "import jwt\n\n"
            "def handle_request(token):\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])\n"
            "    if payload['aud'] != RESOURCE_ID:\n"
            "        raise ValueError('wrong audience')\n"
            "    return payload\n"
        )
        assert not _scan(tmp_path, "server.py", src, "ns-aiml-159")


class TestNsAiml134RedirectUri:
    """Item 3: prefix-matched redirect URI, or DCR ingesting redirect_uris
    with no visible allowlist."""

    def test_python_prefix_match_flagged(self, tmp_path):
        src = (
            "def validate_redirect(redirect_uri, registered_uri):\n"
            "    if not redirect_uri.startswith(registered_uri):\n"
            "        raise ValueError('bad redirect')\n"
            "    return True\n"
        )
        assert _scan(tmp_path, "oauth.py", src, "ns-aiml-160")

    def test_ts_prefix_match_flagged(self, tmp_path):
        src = (
            "function validateRedirect(redirectUri: string, registeredUri: string): boolean {\n"
            "  if (!redirectUri.startsWith(registeredUri)) {\n"
            '    throw new Error("bad redirect");\n'
            "  }\n"
            "  return true;\n"
            "}\n"
        )
        assert _scan(tmp_path, "oauth.ts", src, "ns-aiml-160")

    def test_python_dcr_unvalidated_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def register_client():\n"
            "    redirect_uris = request.json.get('redirect_uris')\n"
            "    client = create_client(redirect_uris=redirect_uris)\n"
            "    return client\n"
        )
        assert _scan(tmp_path, "dcr.py", src, "ns-aiml-160")

    def test_ts_dcr_unvalidated_flagged(self, tmp_path):
        src = (
            'app.post("/register", (req, res) => {\n'
            "  const redirectUris = req.body.redirect_uris;\n"
            "  const client = createClient({ redirectUris });\n"
            "  res.json(client);\n"
            "});\n"
        )
        assert _scan(tmp_path, "dcr.ts", src, "ns-aiml-160")

    def test_exact_match_list_not_flagged(self, tmp_path):
        src = (
            "def validate_redirect(redirect_uri, registered_uris):\n"
            "    if redirect_uri not in registered_uris:\n"
            "        raise ValueError('bad redirect')\n"
            "    return True\n"
        )
        assert not _scan(tmp_path, "oauth.py", src, "ns-aiml-160")

    def test_ts_exact_match_list_not_flagged(self, tmp_path):
        src = (
            "function validateRedirect(redirectUri: string, registeredUris: string[]): boolean {\n"
            "  if (!registeredUris.includes(redirectUri)) {\n"
            '    throw new Error("bad redirect");\n'
            "  }\n"
            "  return true;\n"
            "}\n"
        )
        assert not _scan(tmp_path, "oauth.ts", src, "ns-aiml-160")

    def test_dcr_with_allowlist_not_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "ALLOWED_REDIRECT_HOSTS = {'app.example.com'}\n\n"
            "def register_client():\n"
            "    redirect_uris = request.json.get('redirect_uris')\n"
            "    for uri in redirect_uris:\n"
            "        if urlparse(uri).hostname not in ALLOWED_REDIRECT_HOSTS:\n"
            "            raise ValueError('bad redirect')\n"
            "    client = create_client(redirect_uris=redirect_uris)\n"
            "    return client\n"
        )
        assert not _scan(tmp_path, "dcr.py", src, "ns-aiml-160")

    def test_ordinary_authorize_endpoint_reading_its_own_redirect_uri_not_flagged(self, tmp_path):
        """Regression: an ordinary /authorize handler reading its OWN
        singular `redirect_uri` query parameter is completely normal OAuth
        flow, not DCR. The DCR sub-pattern must require the plural
        `redirect_uris` RFC 7591 actually uses -- an earlier draft of this
        rule made the 's' optional and fired on every /authorize handler."""
        src = (
            "from flask import request\n\n"
            '@app.route("/oauth/authorize")\n'
            "def authorize():\n"
            "    client_id = request.args.get('client_id')\n"
            "    redirect_uri = request.args.get('redirect_uri')\n"
            "    return render_consent_page(client_id, redirect_uri)\n"
        )
        assert not _scan(tmp_path, "authorize.py", src, "ns-aiml-160")


class TestNsAiml135SessionIdAsAuth:
    """Item 4: session id as the apparent basis for authentication, or
    generated predictably."""

    def test_python_session_only_auth_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def authenticate():\n"
            "    session_id = request.headers.get('Mcp-Session-Id')\n"
            "    user = SESSIONS.get(session_id)\n"
            "    return user\n"
        )
        assert _scan(tmp_path, "auth.py", src, "ns-aiml-161")

    def test_ts_session_only_auth_flagged(self, tmp_path):
        src = (
            "app.use((req, res, next) => {\n"
            '  const sessionId = req.headers["mcp-session-id"];\n'
            "  const user = sessions.get(sessionId);\n"
            "  req.user = user;\n"
            "  next();\n"
            "});\n"
        )
        assert _scan(tmp_path, "auth.ts", src, "ns-aiml-161")

    def test_uuid1_session_id_flagged(self, tmp_path):
        src = (
            "import uuid\n\n"
            "def create_session():\n"
            "    session_id = str(uuid.uuid1())\n"
            "    return session_id\n"
        )
        assert _scan(tmp_path, "session.py", src, "ns-aiml-161")

    def test_timestamp_session_id_flagged(self, tmp_path):
        src = (
            "import time\n\n"
            "def create_session():\n"
            "    session_id = str(int(time.time()))\n"
            "    return session_id\n"
        )
        assert _scan(tmp_path, "session.py", src, "ns-aiml-161")

    def test_ts_datenow_session_id_flagged(self, tmp_path):
        src = (
            "function createSession(): string {\n"
            "  const sessionId = Date.now().toString();\n"
            "  return sessionId;\n"
            "}\n"
        )
        assert _scan(tmp_path, "session.ts", src, "ns-aiml-161")

    def test_session_id_plus_bearer_auth_not_flagged(self, tmp_path):
        """The session id is present but is not the sole authentication
        mechanism -- a real bearer token is verified alongside it."""
        src = (
            "from flask import request\n"
            "import jwt\n\n"
            "def authenticate():\n"
            "    session_id = request.headers.get('Mcp-Session-Id')\n"
            "    token = request.headers.get('Authorization')\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'], audience=RESOURCE_ID)\n"
            "    user = SESSIONS.get(session_id)\n"
            "    return user\n"
        )
        assert not _scan(tmp_path, "auth.py", src, "ns-aiml-161")

    def test_uuid4_session_id_not_flagged(self, tmp_path):
        """uuid4 is cryptographically random -- the safe generator."""
        src = (
            "import uuid\n\n"
            "def create_session():\n"
            "    session_id = str(uuid.uuid4())\n"
            "    return session_id\n"
        )
        assert not _scan(tmp_path, "session.py", src, "ns-aiml-161")


class TestNsAiml136ConsentAndAsMetadata:
    """Item 5: wildcard resource indicator, client-supplied AS URL, or
    missing PKCE."""

    def test_wildcard_resource_indicator_flagged(self, tmp_path):
        src = (
            "def register_resource():\n"
            "    resource_indicators = ['*']\n"
            "    return resource_indicators\n"
        )
        assert _scan(tmp_path, "oauth.py", src, "ns-aiml-162")

    def test_ts_wildcard_resource_indicator_flagged(self, tmp_path):
        src = (
            "function registerResource() {\n"
            '  const resourceIndicators = ["*"];\n'
            "  return resourceIndicators;\n"
            "}\n"
        )
        assert _scan(tmp_path, "oauth.ts", src, "ns-aiml-162")

    def test_client_supplied_as_url_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def start_auth():\n"
            "    authorization_server = request.args.get('as_url')\n"
            "    return redirect(authorization_server)\n"
        )
        assert _scan(tmp_path, "oauth.py", src, "ns-aiml-162")

    def test_python_authorize_no_pkce_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            '@app.route("/oauth/authorize")\n'
            "def authorize():\n"
            "    client_id = request.args.get('client_id')\n"
            "    redirect_uri = request.args.get('redirect_uri')\n"
            "    return render_consent_page(client_id, redirect_uri)\n"
        )
        assert _scan(tmp_path, "authorize.py", src, "ns-aiml-162")

    def test_ts_authorize_no_pkce_flagged(self, tmp_path):
        src = (
            'app.get("/oauth/authorize", (req, res) => {\n'
            "  const clientId = req.query.client_id;\n"
            "  const redirectUri = req.query.redirect_uri;\n"
            '  res.render("consent", { clientId, redirectUri });\n'
            "});\n"
        )
        assert _scan(tmp_path, "authorize.ts", src, "ns-aiml-162")

    def test_scoped_resource_indicator_not_flagged(self, tmp_path):
        src = (
            "def register_resource():\n"
            "    resource_indicators = ['https://mcp.example.com']\n"
            "    return resource_indicators\n"
        )
        assert not _scan(tmp_path, "oauth.py", src, "ns-aiml-162")

    def test_fixed_as_url_not_flagged(self, tmp_path):
        src = (
            "AUTHORIZATION_SERVER = 'https://auth.example.com'\n\n"
            "def start_auth():\n"
            "    authorization_server = AUTHORIZATION_SERVER\n"
            "    return redirect(authorization_server)\n"
        )
        assert not _scan(tmp_path, "oauth.py", src, "ns-aiml-162")

    def test_python_authorize_with_pkce_not_flagged(self, tmp_path):
        src = (
            "from flask import request\n\n"
            '@app.route("/oauth/authorize")\n'
            "def authorize():\n"
            "    client_id = request.args.get('client_id')\n"
            "    code_challenge = request.args.get('code_challenge')\n"
            "    if not code_challenge:\n"
            "        raise ValueError('PKCE required')\n"
            "    return render_consent_page(client_id, code_challenge)\n"
        )
        assert not _scan(tmp_path, "authorize.py", src, "ns-aiml-162")

    def test_ts_authorize_with_pkce_not_flagged(self, tmp_path):
        src = (
            'app.get("/oauth/authorize", (req, res) => {\n'
            "  const clientId = req.query.client_id;\n"
            "  const codeChallenge = req.query.code_challenge;\n"
            "  if (!codeChallenge) {\n"
            '    throw new Error("PKCE required");\n'
            "  }\n"
            '  res.render("consent", { clientId, codeChallenge });\n'
            "});\n"
        )
        assert not _scan(tmp_path, "authorize.ts", src, "ns-aiml-162")


class TestNoOverlapWithExistingMcpRules:
    """DEF-10's lesson, per issue #187's own acceptance criteria: the new
    rules must not double-report against the existing TNT-ML-024/025
    fixtures (tests/test_mcp_tool_poisoning_confused_deputy.py)."""

    def test_tool_poisoning_fixture_does_not_trigger_new_rules(self, tmp_path):
        src = (
            "import httpx\n"
            "server = object()\n"
            "remote_desc = httpx.get('https://registry.example.com/desc').json()['description']\n"
            "server.add_tool(name='search', description=remote_desc)\n"
        )
        fp = tmp_path / "tool_poison.py"
        fp.write_text(src, encoding="utf-8")
        hits = [
            r.metadata.id
            for r in _RULES
            if r.metadata.id in ("ns-aiml-159", "ns-aiml-160", "ns-aiml-161", "ns-aiml-162")
            and r.check(fp)
        ]
        assert hits == []

    def test_confused_deputy_fixture_does_not_trigger_new_rules(self, tmp_path):
        src = (
            "import os\n"
            "import httpx\n"
            "UPSTREAM_TOKEN = os.environ['UPSTREAM_API_KEY']\n\n"
            "@mcp.tool()\n"
            "async def fetch_account(account_id):\n"
            "    client = httpx.Client()\n"
            "    resp = client.get(f'https://upstream.example.com/accounts/{account_id}', "
            "headers={'Authorization': UPSTREAM_TOKEN})\n"
            "    return resp.json()\n"
        )
        fp = tmp_path / "confused_deputy.py"
        fp.write_text(src, encoding="utf-8")
        hits = [
            r.metadata.id
            for r in _RULES
            if r.metadata.id in ("ns-aiml-159", "ns-aiml-160", "ns-aiml-161", "ns-aiml-162")
            and r.check(fp)
        ]
        assert hits == []


@_needs_opengrep
class TestConvertedEngineDefaultParity:
    """`ScanConfig.legacy_neuroscan` defaults to `False` -- the DEFAULT scan
    path compiles every NeuroScan rule to Opengrep `pattern-regex`/
    `pattern-not-regex` (`scripts/convert_neuroscan_to_opengrep.py`) and runs
    it through the real Opengrep binary, NOT through `NeuroScanRule.check`.

    That converter marks any rule using the windowed `sanitizers:` field
    `residual: sanitizer` -- the field is silently NOT carried over. Verified
    empirically (not assumed) that this is a real, live false-positive gap in
    the current shipped product, not unique to this PR: the ALREADY-SHIPPED
    `ns-aiml-127` (auth_provider-guarded MCP transport) fires on its own
    documented-safe fixture when scanned through `rules/converted/
    ai_security.yaml`, the exact path a default `rowan scan` takes.

    Also verified that a BARE, unanchored `pattern-not-regex` term (the
    naive fix -- just listing the sanitizer words in `pattern-not` too) does
    NOT help: Opengrep only suppresses a match whose range OVERLAPS the
    negative regex's own match. A term like `audience=` sitting elsewhere in
    the file, not overlapping the `jwt.decode(` match, does not suppress it.
    Confirmed with a two-call fixture (one safe, one not) that gets exactly
    one finding at the correct line once the pattern-not-regex is anchored
    to the SAME prefix as the positive pattern and spans forward
    (`jwt\\.decode\\([\\s\\S]{0,400}?audience...`) -- that shape is what
    ns-aiml-159/134/135/136 ship with, verified by every test below actually
    exercising the real converted file through the real Opengrep binary
    rather than only `NeuroScanRule.check`.

    This is a systemic defect affecting every rule in the corpus that uses
    `sanitizers:` (the converter reports "Sanitizer residual: 181" across
    the whole ruleset) -- filed separately as its own issue rather than
    fixed generally here, since a general fix touches the shared converter
    and needs verifying against all 181 affected rules, not just these 4.
    """

    def test_audience_present_same_line_not_flagged_by_default_engine(self, tmp_path):
        src = (
            "import jwt\n\n"
            "def handle_request(token):\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'], audience=RESOURCE_ID)\n"
            "    return payload\n"
        )
        assert not _scan_converted(tmp_path, "server.py", src, "ns-aiml-159")

    def test_audience_present_multiline_not_flagged_by_default_engine(self, tmp_path):
        """The case that actually needs the span-based anchor: the audience
        kwarg is a few lines below the call it belongs to, which is how
        Python code with several kwargs is typically formatted."""
        src = (
            "import jwt\n\n"
            "def handle_request(token):\n"
            "    payload = jwt.decode(\n"
            "        token,\n"
            "        PUBLIC_KEY,\n"
            "        algorithms=['RS256'],\n"
            "        audience=RESOURCE_ID,\n"
            "    )\n"
            "    return payload\n"
        )
        assert not _scan_converted(tmp_path, "server.py", src, "ns-aiml-159")

    def test_no_audience_still_flagged_by_default_engine(self, tmp_path):
        """Control: the anchoring fix must not have accidentally suppressed
        the genuine positive too."""
        src = (
            "import jwt\n\n"
            "def handle_request(token):\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'])\n"
            "    return payload\n"
        )
        assert _scan_converted(tmp_path, "server.py", src, "ns-aiml-159")

    def test_dcr_with_allowlist_not_flagged_by_default_engine(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "ALLOWED_REDIRECT_HOSTS = {'app.example.com'}\n\n"
            "def register_client():\n"
            "    redirect_uris = request.json.get('redirect_uris')\n"
            "    for uri in redirect_uris:\n"
            "        if urlparse(uri).hostname not in ALLOWED_REDIRECT_HOSTS:\n"
            "            raise ValueError('bad redirect')\n"
            "    client = create_client(redirect_uris=redirect_uris)\n"
            "    return client\n"
        )
        assert not _scan_converted(tmp_path, "dcr.py", src, "ns-aiml-160")

    def test_dcr_unvalidated_still_flagged_by_default_engine(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def register_client():\n"
            "    redirect_uris = request.json.get('redirect_uris')\n"
            "    client = create_client(redirect_uris=redirect_uris)\n"
            "    return client\n"
        )
        assert _scan_converted(tmp_path, "dcr.py", src, "ns-aiml-160")

    def test_session_id_with_bearer_auth_not_flagged_by_default_engine(self, tmp_path):
        src = (
            "from flask import request\n"
            "import jwt\n\n"
            "def authenticate():\n"
            "    session_id = request.headers.get('Mcp-Session-Id')\n"
            "    token = request.headers.get('Authorization')\n"
            "    payload = jwt.decode(token, PUBLIC_KEY, algorithms=['RS256'], audience=RESOURCE_ID)\n"
            "    user = SESSIONS.get(session_id)\n"
            "    return user\n"
        )
        assert not _scan_converted(tmp_path, "auth.py", src, "ns-aiml-161")

    def test_session_id_only_auth_still_flagged_by_default_engine(self, tmp_path):
        src = (
            "from flask import request\n\n"
            "def authenticate():\n"
            "    session_id = request.headers.get('Mcp-Session-Id')\n"
            "    user = SESSIONS.get(session_id)\n"
            "    return user\n"
        )
        assert _scan_converted(tmp_path, "auth.py", src, "ns-aiml-161")

    def test_authorize_with_pkce_not_flagged_by_default_engine(self, tmp_path):
        src = (
            "from flask import request\n\n"
            '@app.route("/oauth/authorize")\n'
            "def authorize():\n"
            "    client_id = request.args.get('client_id')\n"
            "    code_challenge = request.args.get('code_challenge')\n"
            "    if not code_challenge:\n"
            "        raise ValueError('PKCE required')\n"
            "    return render_consent_page(client_id, code_challenge)\n"
        )
        assert not _scan_converted(tmp_path, "authorize.py", src, "ns-aiml-162")

    def test_authorize_without_pkce_still_flagged_by_default_engine(self, tmp_path):
        src = (
            "from flask import request\n\n"
            '@app.route("/oauth/authorize")\n'
            "def authorize():\n"
            "    client_id = request.args.get('client_id')\n"
            "    redirect_uri = request.args.get('redirect_uri')\n"
            "    return render_consent_page(client_id, redirect_uri)\n"
        )
        assert _scan_converted(tmp_path, "authorize.py", src, "ns-aiml-162")

    def test_preexisting_ns_aiml_127_has_the_same_gap(self, tmp_path):
        """Not a regression test for THIS PR's rules -- documents that the
        gap this whole class works around is pre-existing and shipped
        already, via the already-merged ns-aiml-127 (MCP network transport
        without an auth provider). Its own documented-safe fixture
        (auth_provider present) still fires through the converted engine,
        because ns-aiml-127 was never given the same anchored pattern-not
        treatment. If this test starts failing, ns-aiml-127 has been fixed
        and this test (not the rule) should be updated."""
        src = (
            "mcp = object()\n"
            'mcp.run(transport="sse", auth_provider=BearerAuthProvider())\n'
        )
        assert _scan_converted(tmp_path, "server.py", src, "ns-aiml-127"), (
            "if this is empty, ns-aiml-127's converted-engine sanitizer gap "
            "has been fixed -- update this test to assert the safe case, "
            "and consider whether the general fix this documents is now done"
        )


@_needs_opengrep
class TestDef46FunctionBoundaryGuard:
    """DEF-46 (found via issue #197's benchmark work, not assumed): the
    anchored-span `pattern-not-regex` technique above (added to close DEF-45)
    had its own gap. A span like `jwt\\.decode\\([\\s\\S]{0,400}?audience...`
    has no notion of a FUNCTION boundary -- when a vulnerable function and
    its safe sibling sit close together in real code (exactly how a
    benchmark corpus, or any codebase with an old/new function pair, is
    naturally authored), the safe sibling's own `audience=` term leaks
    BACKWARD across the intervening `def` line and incorrectly suppresses
    the vulnerable function's own finding.

    Reproduced against a real fixture in the ModelForge/langfail benchmark
    corpus while building issue #197's tier: `verify_mcp_token` (no
    audience check) sat ~14 lines above its own safe sibling
    `verify_mcp_token_safe` (which does check audience) in the same file,
    and `ns-aiml-159` silently produced ZERO findings for the vulnerable
    function -- a false negative in the shipped rule, not merely a
    theoretical risk.

    Fixed by requiring the span to stop at the next `\\ndef ` -- with a
    special case for `ns-aiml-162`'s `@app.route(...)` anchor, which is
    ALWAYS immediately followed by its own paired `def NAME(...):` line, so
    that one intentional crossing has to stay allowed while a second,
    unrelated one still stops the span.
    """

    def test_vuln_with_adjacent_safe_sibling_still_flagged(self, tmp_path):
        """The exact shape that caused DEF-46: a vulnerable function
        immediately followed by its safe sibling, close enough that the
        sibling's own `audience=` term falls inside the anchored span."""
        src = (
            "import jwt\n\n"
            "def verify_token(token):\n"
            "    try:\n"
            "        return jwt.decode(token, SECRET, algorithms=['HS256'])\n"
            "    except jwt.PyJWTError:\n"
            "        return None\n\n"
            "def verify_token_safe(token):\n"
            "    try:\n"
            "        return jwt.decode(token, SECRET, algorithms=['HS256'], audience=RESOURCE_ID)\n"
            "    except jwt.PyJWTError:\n"
            "        return None\n"
        )
        findings = _scan_converted(tmp_path, "security.py", src, "ns-aiml-159")
        assert findings, (
            "DEF-46 regression: the vulnerable verify_token must still be flagged "
            "even though its safe sibling's audience= term sits just past the def boundary"
        )
        assert findings[0].start_line < 8, "the finding must land on verify_token, not verify_token_safe"

    def test_adjacent_safe_sibling_itself_still_clean(self, tmp_path):
        """The other half: the safe sibling itself must stay unflagged --
        the fix must not overcorrect into a blanket false positive."""
        src = (
            "import jwt\n\n"
            "def verify_token(token):\n"
            "    try:\n"
            "        return jwt.decode(token, SECRET, algorithms=['HS256'])\n"
            "    except jwt.PyJWTError:\n"
            "        return None\n\n"
            "def verify_token_safe(token):\n"
            "    try:\n"
            "        return jwt.decode(token, SECRET, algorithms=['HS256'], audience=RESOURCE_ID)\n"
            "    except jwt.PyJWTError:\n"
            "        return None\n"
        )
        findings = _scan_converted(tmp_path, "security.py", src, "ns-aiml-159")
        assert all(f.start_line < 8 for f in findings), (
            "verify_token_safe (line 9's jwt.decode) must not be flagged"
        )

    def test_route_decorator_pkce_still_suppresses_across_its_own_def_line(self, tmp_path):
        """The @app.route special case: the guard must still allow crossing
        the ONE expected def line between a route decorator and its own
        function body."""
        src = (
            "from flask import request\n\n"
            '@app.route("/oauth/authorize")\n'
            "def authorize():\n"
            "    client_id = request.args.get('client_id')\n"
            "    code_challenge = request.args.get('code_challenge')\n"
            "    if not code_challenge:\n"
            "        raise ValueError('PKCE required')\n"
            "    return render_consent_page(client_id, code_challenge)\n"
        )
        assert not _scan_converted(tmp_path, "authorize.py", src, "ns-aiml-162"), (
            "DEF-46 regression: the unqualified boundary guard produced a false "
            "positive here by blocking the decorator from reaching its own function's PKCE check"
        )

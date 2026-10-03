"""One input registry and one LLM-sink registry (BACKLOG CN-05: TE-06, TE-07,
TE-24, AZ-20)."""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.analysis.request_sources import HTTP_INPUT_RE
from rowan.config import ScanConfig
from rowan.core.findings import Category, Finding, ScanResult, Severity
from rowan.core.llm_sources import LLM_COMPLETION_RE
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import _SOURCE_HTTP_RE, _WEB_INPUT_RE, EnrichmentPass
from rowan.passes.pii_egress import PiiEgressPass


class TestHttpInputRegistry:
    def test_enrichment_regexes_derive_from_the_registry(self):
        # TE-24: the three lists must agree on what HTTP input is.
        for snippet in (
            "request.args.get('q')",
            "request.get_json()",
            "request.cookies['s']",
            "request.path_params['id']",
            "q: str = Query(None)",
            "p: int = Path(...)",
            "f: UploadFile = Form(...)",
            "h: str | None = Header(None)",
            "c: str = Cookie(None)",
        ):
            assert HTTP_INPUT_RE.search(snippet), snippet
            assert _SOURCE_HTTP_RE.search(snippet), snippet
            assert _WEB_INPUT_RE.search(snippet), snippet

    def test_pathlib_and_bare_calls_are_not_input(self):
        for snippet in (
            "p = pathlib.Path('/tmp')",
            "root = Path(base) / name",
            "results = Query(db).all()",
            "def f(x) -> Path:\n    module_rel = Path(x)",
        ):
            assert not HTTP_INPUT_RE.search(snippet), snippet

    def test_web_input_also_sees_route_decorators(self):
        assert _WEB_INPUT_RE.search("@app.get('/items/{item_id}')")
        assert _WEB_INPUT_RE.search("@router.post('/x')")


class TestUuidSuppressionScope:
    """TE-07: `import uuid` at the top of a file must not demote every SQL
    finding in it; only a uuid conversion near the sink does."""

    def _run(self, tmp_path: Path, src: str, line: int) -> Finding:
        p = tmp_path / "db.py"
        p.write_text(src, encoding="utf-8")
        f = Finding(
            rule_id="NS-SQLI-001",
            message="sql",
            severity=Severity.HIGH,
            category=Category.INJECTION,
            file_path=str(p),
            start_line=line,
            engine="opengrep",
        )
        return EnrichmentPass()._suppress_uuid_sql_targets([f])[0]

    def test_uuid_import_alone_does_not_demote(self, tmp_path):
        src = "import uuid\n\ndef q(cur, name):\n    cur.execute('SELECT * FROM t WHERE n = ' + name)\n"
        assert self._run(tmp_path, src, 4).severity == Severity.HIGH

    def test_uuid_conversion_next_to_the_sink_still_demotes(self, tmp_path):
        src = "import uuid\n\ndef q(cur, raw):\n    rid = uuid.UUID(raw)\n    cur.execute('SELECT * FROM t WHERE id = ' + str(rid))\n"
        assert self._run(tmp_path, src, 5).severity == Severity.INFO

    def test_fastapi_query_param_counts_as_web_input(self, tmp_path):
        src = (
            "import uuid\nfrom fastapi import Query\n\n"
            "def q(cur, name: str = Query(None)):\n"
            "    rid = uuid.uuid4()\n"
            "    cur.execute('SELECT * FROM t WHERE n = ' + name)\n"
        )
        assert self._run(tmp_path, src, 6).severity == Severity.HIGH


class TestLlmCompletionShapes:
    @pytest.mark.parametrize(
        "snippet",
        [
            "getattr(self, tool_call.function.name)",
            "handlers[block.name](**block.input)",
            "client.responses.create(model=m, input=q)",
            "client.messages.stream(model=m, messages=msgs)",
            "model.generate_content(prompt)",
            "client.chat.completions.parse(model=m, messages=msgs)",
        ],
    )
    def test_tool_name_and_newer_sdk_shapes_are_llm_output(self, snippet):
        # TE-06 / AZ-20
        assert LLM_COMPLETION_RE.search(snippet), snippet


def _pii_scan(tmp_path: Path, backend: str) -> list[Finding]:
    files = {
        "backend.py": backend,
        "agent.py": (
            "from backend import llm_send\n\n"
            "def run_agent(question, context_docs=None):\n"
            "    messages = []\n"
            "    for doc in context_docs or []:\n"
            "        messages.append({'role': 'user', 'content': doc})\n"
            "    messages.append({'role': 'user', 'content': question})\n"
            "    return llm_send(messages)\n"
        ),
        "support.py": (
            "from agent import run_agent\n\n"
            "def account_context(user):\n"
            "    return f'Account email={user.email}'\n\n"
            "def draft(user, question):\n"
            "    return run_agent(question, context_docs=[account_context(user)])\n"
        ),
    }
    for name, src in files.items():
        (tmp_path / name).write_text(src, encoding="utf-8")
    ctx = ScanContext(target_path=tmp_path, config=ScanConfig(target=tmp_path), result=ScanResult())
    return PiiEgressPass().run(ctx).findings


@pytest.mark.parametrize(
    "sink",
    [
        "client.responses.create(model='m', input=messages)",
        "client.messages.stream(model='m', messages=messages)",
        "model.generate_content(messages)",
        "llm.invoke(messages)",
    ],
)
def test_pii_egress_recognises_newer_llm_sinks(tmp_path, sink):
    # AZ-20
    backend = f"def llm_send(messages):\n    return {sink}\n"
    hits = _pii_scan(tmp_path, backend)
    assert len(hits) == 1, [h.rule_id for h in hits]

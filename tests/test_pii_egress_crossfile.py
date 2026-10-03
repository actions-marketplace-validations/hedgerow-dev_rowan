"""LF-6 V38 interprocedural PII egress fixtures."""

from rowan.config import ScanConfig
from rowan.core.findings import ScanResult
from rowan.passes.base import ScanContext
from rowan.passes.pii_egress import PiiEgressPass


def _scan(tmp_path, files):
    for name, source in files.items():
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(source, encoding="utf-8")
    context = ScanContext(
        target_path=tmp_path,
        config=ScanConfig(target=tmp_path),
        result=ScanResult(),
    )
    return PiiEgressPass().run(context).findings


_BACKEND = (
    "def llm_send(messages):\n"
    "    payload = {'messages': messages}\n"
    "    return requests.post(settings.LLM_URL, json=payload)\n"
)
_AGENT = (
    "from backend import llm_send\n\n"
    "def run_agent(question, context_docs=None):\n"
    "    messages = []\n"
    "    for doc in context_docs or []:\n"
    "        messages.append({'role': 'user', 'content': doc})\n"
    "    messages.append({'role': 'user', 'content': question})\n"
    "    return llm_send(messages)\n"
)


def test_database_email_crosses_wrappers_into_llm_request(tmp_path):
    hits = _scan(tmp_path, {
        "backend.py": _BACKEND,
        "agent.py": _AGENT,
        "support.py": (
            "from agent import run_agent\n\n"
            "def account_context(user):\n"
            "    return f'Account email={user.email}'\n\n"
            "def draft(user, question):\n"
            "    return run_agent(question, context_docs=[account_context(user)])\n"
        ),
    })
    assert len(hits) == 1
    assert hits[0].rule_id == "TNT-ML-PII-EGRESS-001"
    assert hits[0].file_path.endswith("support.py")
    assert hits[0].start_line == 7


def test_redaction_before_agent_wrapper_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "backend.py": _BACKEND,
        "agent.py": _AGENT,
        "support.py": (
            "from agent import run_agent\n\n"
            "def account_context(user):\n"
            "    return f'Account email={user.email}'\n\n"
            "def draft(user, question):\n"
            "    context = redact_email(account_context(user))\n"
            "    return run_agent(question, context_docs=[context])\n"
        ),
    })
    assert hits == []


def test_literal_local_llm_client_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "local.py": (
            "def summarize(user):\n"
            "    client = OpenAI(base_url='http://localhost:11434/v1')\n"
            "    prompt = f'Account email={user.email}'\n"
            "    return client.chat.completions.create(messages=[{'content': prompt}])\n"
        )
    })
    assert hits == []


def test_dominating_consent_rejection_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "remote.py": (
            "def summarize(user, client):\n"
            "    if not user.llm_consent:\n"
            "        return {'error': 'consent required'}\n"
            "    prompt = f'Account email={user.email}'\n"
            "    return client.chat.completions.create(messages=[{'content': prompt}])\n"
        )
    })
    assert hits == []


def test_non_pii_database_field_is_safe(tmp_path):
    hits = _scan(tmp_path, {
        "remote.py": (
            "def summarize(user, client):\n"
            "    prompt = f'Account tier={user.plan_tier}'\n"
            "    return client.chat.completions.create(messages=[{'content': prompt}])\n"
        )
    })
    assert hits == []

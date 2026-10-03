"""Fixtures for TNT-ML-014 (rules/agent_taint.yaml): PII-shaped ORM/DB
field flowing into a third-party LLM completion/embedding call with no
visible redaction step (issue #140).

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see
.github/workflows/ci.yml).

Acceptance-criteria fixtures covered here:
  - PII redacted via presidio (clean) vs raw PII (finding) -- see
    TestPresidioRedaction below.
  - "Localhost base_url suppression tested" -- TestLocalhostBaseUrl below
    tests this and currently documents (via an xfail-style assertion, see
    that class's own docstring) that this specific suppression is NOT
    mechanically implemented, per TNT-ML-014's own engine note in
    rules/agent_taint.yaml explaining why a base_url-on-the-client-object
    sanitizer can't intercept the source-to-sink path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULE_FILE = "agent_taint.yaml"

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path, filename, source, rule_id):
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / RULE_FILE], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


class TestRawPiiEgressFlagged:
    def test_orm_attribute_pii_into_chat_completion_flagged(self, tmp_path):
        # The issue's own example: User.dob / User.diagnosis interpolated
        # directly into a prompt sent to an external chat completion call.
        src = (
            "def summarize(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    prompt = f'Summarize this patient: {user.name}, DOB {user.dob}, dx {user.diagnosis}'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "patient_summary.py", src, "TNT-ML-014")
        assert findings, "user.dob / user.diagnosis reaching a chat completion call must be flagged"

    def test_dict_subscript_ssn_into_completion_flagged(self, tmp_path):
        # issue example: row["ssn"] dict-style access.
        src = (
            "def support_reply(client, row):\n"
            "    ssn = row['ssn']\n"
            "    prompt = f'Verify account for SSN {ssn}'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_row.py", src, "TNT-ML-014")
        assert findings, "row['ssn'] reaching a chat completion call must be flagged"

    def test_salary_into_embeddings_create_flagged(self, tmp_path):
        # New sink added for issue #140: embeddings API is also third-party
        # egress for PII, not just chat completions.
        src = (
            "def embed_profile(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    text = f'Employee profile, salary: {user.salary}'\n"
            "    return client.embeddings.create(model='text-embedding-3-small', input=text)\n"
        )
        findings = _scan(tmp_path, "embed_salary.py", src, "TNT-ML-014")
        assert findings, "user.salary reaching embeddings.create() must be flagged"


class TestPresidioRedaction:
    """Acceptance criterion: presidio-redacted PII (clean) vs raw (finding)."""

    def test_raw_email_unredacted_flagged(self, tmp_path):
        src = (
            "def support_reply(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    prompt = f'Contact the user at {user.email} about their ticket'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_raw.py", src, "TNT-ML-014")
        assert findings, "raw user.email interpolated into a prompt must be flagged"

    def test_presidio_anonymized_email_not_flagged(self, tmp_path):
        src = (
            "from presidio_analyzer import AnalyzerEngine\n"
            "from presidio_anonymizer import AnonymizerEngine\n\n"
            "def support_reply(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    analyzer = AnalyzerEngine()\n"
            "    anonymizer = AnonymizerEngine()\n"
            "    results = analyzer.analyze(text=user.email, language='en')\n"
            "    safe_email = anonymizer.anonymize(text=user.email, analyzer_results=results).text\n"
            "    prompt = f'Contact the user at {safe_email} about their ticket'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_presidio.py", src, "TNT-ML-014")
        assert not findings, (
            "presidio AnonymizerEngine().anonymize(...).text reassignment "
            "must suppress the finding"
        )

    def test_scrubadub_cleaned_text_not_flagged(self, tmp_path):
        src = (
            "import scrubadub\n\n"
            "def support_reply(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    raw_note = f'Patient DOB: {user.dob}'\n"
            "    clean_note = scrubadub.clean(raw_note)\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': clean_note}])\n"
        )
        findings = _scan(tmp_path, "support_scrubadub.py", src, "TNT-ML-014")
        assert not findings, "scrubadub.clean(...) reassignment must suppress the finding"

    def test_custom_redact_helper_not_flagged(self, tmp_path):
        src = (
            "def support_reply(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    safe_phone = redact(user.phone)\n"
            "    prompt = f'Callback number: {safe_phone}'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_redact.py", src, "TNT-ML-014")
        assert not findings, "a custom redact() reassignment must suppress the finding"

    def test_custom_pseudonymize_helper_matched_via_regex_not_flagged(self, tmp_path):
        # Exercises the generic metavariable-regex sanitizer (redact|
        # anonymi[sz]e|mask|pseudonym) against a project-specific function
        # name that isn't one of the explicitly-listed literals.
        src = (
            "def support_reply(client, uid):\n"
            "    user = db.query(User).get(uid)\n"
            "    safe_address = pseudonymize_field(user.address)\n"
            "    prompt = f'Ship to: {safe_address}'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_pseudonymize.py", src, "TNT-ML-014")
        assert not findings, (
            "a custom pseudonymize_field() reassignment must be caught by the "
            "generic redact|anonymi[sz]e|mask|pseudonym metavariable-regex sanitizer"
        )


class TestLocalhostBaseUrl:
    """Acceptance criterion: 'localhost base_url suppression tested'.

    Implemented as a sink-level `pattern-not-inside` (see TNT-ML-014's own
    engine note in rules/agent_taint.yaml for why this needed a structural
    exclusion rather than a pattern-sanitizer, and for how it was
    empirically verified against a live opengrep binary before landing).
    """

    def test_localhost_base_url_suppresses_finding(self, tmp_path):
        src = (
            "def support_reply(uid):\n"
            "    client = OpenAI(base_url='http://localhost:11434/v1', api_key='unused')\n"
            "    user = db.query(User).get(uid)\n"
            "    prompt = f'Contact the user at {user.email} about their ticket'\n"
            "    return client.chat.completions.create(model='llama3', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_localhost.py", src, "TNT-ML-014")
        assert not findings, (
            "a client constructed with a localhost base_url in the same "
            "function must suppress the finding -- this is not third-party egress"
        )

    def test_127_0_0_1_base_url_suppresses_finding(self, tmp_path):
        src = (
            "def support_reply(uid):\n"
            "    client = OpenAI(base_url='http://127.0.0.1:8000/v1', api_key='unused')\n"
            "    user = db.query(User).get(uid)\n"
            "    prompt = f'Contact the user at {user.email} about their ticket'\n"
            "    return client.chat.completions.create(model='llama3', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_127.py", src, "TNT-ML-014")
        assert not findings, "127.0.0.1 base_url must also suppress the finding"

    def test_remote_base_url_still_flagged(self, tmp_path):
        # Negative control: a same-shaped client construction pointed at a
        # real third-party endpoint must NOT be suppressed by the exclusion.
        src = (
            "def support_reply(uid):\n"
            "    client = OpenAI(base_url='https://api.openai.com/v1', api_key='sk-real')\n"
            "    user = db.query(User).get(uid)\n"
            "    prompt = f'Contact the user at {user.email} about their ticket'\n"
            "    return client.chat.completions.create(model='gpt-4o', messages=[{'role': 'user', 'content': prompt}])\n"
        )
        findings = _scan(tmp_path, "support_remote.py", src, "TNT-ML-014")
        assert findings, (
            "a client pointed at a real third-party base_url must still be "
            "flagged -- the localhost exclusion must not over-suppress"
        )

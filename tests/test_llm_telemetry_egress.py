"""LLM tracing/telemetry egress (issue #193, epic #183).

LLM tracing SDKs capture, by default, the full prompt, the full
completion, tool call arguments, and retrieved RAG documents, and ship
them to a third-party SaaS. TNT-ML-014 covers the INBOUND direction (a
PII-shaped field reaching an LLM call); this closes the OUTBOUND
direction, which was entirely unmodeled before this (zero corpus hits for
langsmith, langfuse, phoenix, braintrust, helicone, wandb tracing,
openllmetry).

  ns-aiml-154  LLM tracing enabled with payload capture on (no redaction
               hook / hide_inputs / hide_outputs / CAPTURE_CONTENT=false
               nearby).
  TNT-ML-032   PII-shaped value reaching a trace/span attribute. Reuses
               TNT-ML-014's PII source recognizer verbatim, per the
               issue's own instruction. (ID chosen to match the corpus's
               id-to-mechanism convention -- the issue text suggested
               "TNT-ML-031", which collides with #192's cache-poisoning
               rule; same class of correction already made for
               ns-aiml-149/151 in #190/#191.)
  ns-aiml-155  self-hosted-vs-SaaS endpoint not pinned (no host=/
               endpoint=/api_url= nearby). Presence signal, severity info.
  ns-sec-003   tracing API key committed (LANGSMITH_API_KEY,
               LANGFUSE_SECRET_KEY/PUBLIC_KEY, PHOENIX_API_KEY,
               WANDB_API_KEY). Uses the "ns-sec-" id prefix rather than
               the issue's suggested "ns-aiml-156" -- NeuroScanRule.
               _is_secret_rule() gates the shared env-reference/
               placeholder/entropy value filter on that literal prefix,
               a functional requirement, not a style choice.

This is a compliance/data-governance category more than an
exploitability one (per the issue's own framing note) -- severity and
message wording reflect that; ns-aiml-155 is explicitly a presence
signal, not a breach claim.

Requires the Opengrep binary (skipped entirely if not installed, matching
the project's convention -- CI does not install it, see .github/workflows/ci.yml).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from rowan.config import ScanConfig
from rowan.core.rules import load_neuroscan_rules
from rowan.pipeline import ScanPipeline
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"
RULES_PATH = RULES_DIR / "ai_security.yaml"
CONVERTED_RULES_PATH = RULES_DIR / "converted" / "ai_security.yaml"
AGENT_TAINT_PATH = RULES_DIR / "agent_taint.yaml"
_RULES = load_neuroscan_rules(RULES_PATH)

_adapter = OpengrepAdapter()
pytestmark = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)

_ALL_LANGS = ["python", "javascript", "typescript", "ai_instructions", "markdown", "dotenv", "dockerfile", "yaml"]


def _scan(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    rule = next(r for r in _RULES if r.metadata.id == rule_id)
    return rule.check(fp)


def _scan_converted(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [CONVERTED_RULES_PATH], languages=_ALL_LANGS)
    return [f for f in findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


def _scan_taint(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(tmp_path, [AGENT_TAINT_PATH], languages=["python"])
    return [f for f in findings if f.rule_id == rule_id]


def _scan_pipeline(tmp_path: Path, filename: str, source: str, rule_id: str) -> list:
    """Full ScanPipeline (runs EnrichmentPass), not the raw adapter -- the
    env-reference/placeholder/entropy value filter for secrets-tagged
    converted rules (ns-sec-003) lives in EnrichmentPass._suppress_secret_
    noise, gated on the manifest's residual: [secrets] tag, not compiled
    into the rule's own pattern-not-regex. _scan_converted (raw adapter)
    correctly shows the un-filtered finding for these two cases; this is
    what the real product pipeline actually reports."""
    fp = tmp_path / filename
    fp.write_text(source, encoding="utf-8")
    result = ScanPipeline(ScanConfig(target=tmp_path, no_sca=True, no_taint=True)).run()
    return [f for f in result.findings if f.rule_id == rule_id and Path(f.file_path).name == filename]


class TestNsAiml154TracingPayloadCapture:
    def test_langfuse_no_redaction_hook_flagged(self, tmp_path):
        src = "langfuse = Langfuse(public_key=pk, secret_key=sk)\n"
        assert _scan(tmp_path, "tracing.py", src, "ns-aiml-154")
        assert _scan_converted(tmp_path, "tracing.py", src, "ns-aiml-154")

    def test_langsmith_client_no_redaction_flagged(self, tmp_path):
        src = "client = langsmith.Client(api_key=key)\n"
        assert _scan(tmp_path, "langsmith_setup.py", src, "ns-aiml-154")
        assert _scan_converted(tmp_path, "langsmith_setup.py", src, "ns-aiml-154")

    def test_langchain_tracing_v2_in_dotenv_flagged(self, tmp_path):
        src = "LANGCHAIN_TRACING_V2=true\nLANGCHAIN_API_KEY=abc\n"
        assert _scan(tmp_path, ".env", src, "ns-aiml-154")
        assert _scan_converted(tmp_path, ".env", src, "ns-aiml-154")

    def test_langchain_tracing_v2_in_dockerfile_flagged(self, tmp_path):
        src = "FROM python:3.12\nENV LANGCHAIN_TRACING_V2=true\n"
        assert _scan(tmp_path, "Dockerfile", src, "ns-aiml-154")
        assert _scan_converted(tmp_path, "Dockerfile", src, "ns-aiml-154")

    def test_langfuse_with_redaction_hook_not_flagged(self, tmp_path):
        src = "langfuse = Langfuse(public_key=pk, secret_key=sk, mask=redact_pii)\n"
        assert _scan(tmp_path, "tracing_safe.py", src, "ns-aiml-154") == []
        assert _scan_converted(tmp_path, "tracing_safe.py", src, "ns-aiml-154") == []

    def test_capture_content_disabled_not_flagged(self, tmp_path):
        src = (
            "phoenix.otel.register(project_name='x')\n"
            "# OTEL_INSTRUMENTATION_GENAI_CAPTURE_CONTENT=false is set in the environment\n"
        )
        assert _scan(tmp_path, "phoenix_safe.py", src, "ns-aiml-154") == []
        assert _scan_converted(tmp_path, "phoenix_safe.py", src, "ns-aiml-154") == []


class TestNsAiml155EndpointNotPinned:
    def test_langsmith_no_host_flagged(self, tmp_path):
        src = "client = langsmith.Client(api_key=key)\n"
        assert _scan(tmp_path, "endpoint.py", src, "ns-aiml-155")
        assert _scan_converted(tmp_path, "endpoint.py", src, "ns-aiml-155")

    def test_self_hosted_internal_endpoint_not_flagged(self, tmp_path):
        src = "client = langsmith.Client(api_key=key, api_url='http://langsmith.internal:1984')\n"
        assert _scan(tmp_path, "endpoint_safe.py", src, "ns-aiml-155") == []
        assert _scan_converted(tmp_path, "endpoint_safe.py", src, "ns-aiml-155") == []


class TestNsSec003TracingApiKeyCommitted:
    def test_langsmith_api_key_committed_flagged(self, tmp_path):
        src = 'LANGSMITH_API_KEY = "ls__abcdef1234567890abcdef1234567890"\n'
        assert _scan(tmp_path, "config.py", src, "ns-sec-003")
        assert _scan_converted(tmp_path, "config.py", src, "ns-sec-003")

    def test_wandb_api_key_committed_in_dotenv_flagged(self, tmp_path):
        src = "WANDB_API_KEY=9f8e7d6c5b4a3928170695a4b3c2d1e0f9a8b7c6\n"
        assert _scan(tmp_path, ".env", src, "ns-sec-003")
        assert _scan_converted(tmp_path, ".env", src, "ns-sec-003")

    def test_langfuse_secret_key_env_reference_not_flagged(self, tmp_path):
        """Converted-engine assertion uses the full pipeline (EnrichmentPass),
        not the raw adapter -- see _scan_pipeline's docstring."""
        src = 'LANGFUSE_SECRET_KEY = os.environ["LANGFUSE_SECRET_KEY"]\n'
        assert _scan(tmp_path, "config_safe.py", src, "ns-sec-003") == []
        assert _scan_pipeline(tmp_path, "config_safe.py", src, "ns-sec-003") == []

    def test_placeholder_value_not_flagged(self, tmp_path):
        """Converted-engine assertion uses the full pipeline (EnrichmentPass),
        not the raw adapter -- see _scan_pipeline's docstring."""
        src = 'PHOENIX_API_KEY = "changeme-placeholder-value"\n'
        assert _scan(tmp_path, "config_placeholder.py", src, "ns-sec-003") == []
        assert _scan_pipeline(tmp_path, "config_placeholder.py", src, "ns-sec-003") == []


class TestTntMl032PiiIntoTraceAttribute:
    def test_email_into_span_set_attribute_flagged(self, tmp_path):
        src = (
            "def handle(user, span):\n"
            "    span.set_attribute('user.email', user.email)\n"
        )
        assert _scan_taint(tmp_path, "trace_pii.py", src, "TNT-ML-032")

    def test_ssn_into_langfuse_trace_flagged(self, tmp_path):
        src = (
            "def handle(user):\n"
            "    langfuse.trace(input=user.ssn)\n"
        )
        assert _scan_taint(tmp_path, "trace_pii2.py", src, "TNT-ML-032")

    def test_phone_into_wandb_log_flagged(self, tmp_path):
        src = (
            "def handle(user):\n"
            "    wandb.log({'contact': user.phone})\n"
        )
        assert _scan_taint(tmp_path, "trace_pii3.py", src, "TNT-ML-032")

    def test_redacted_email_not_flagged(self, tmp_path):
        src = (
            "def handle(user, span):\n"
            "    safe_email = redact(user.email)\n"
            "    span.set_attribute('user.email', safe_email)\n"
        )
        assert _scan_taint(tmp_path, "trace_pii_safe.py", src, "TNT-ML-032") == []

    def test_non_pii_field_into_span_not_flagged(self, tmp_path):
        src = (
            "def handle(user, span):\n"
            "    span.set_attribute('user.plan', user.plan)\n"
        )
        assert _scan_taint(tmp_path, "trace_no_pii.py", src, "TNT-ML-032") == []

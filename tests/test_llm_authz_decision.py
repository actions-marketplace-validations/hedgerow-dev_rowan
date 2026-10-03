"""LLM output used as an authorization decision (issue #185, epic #183).

Three things are covered here, in dependency order:

1. `TNT-AUTHZ-001` -- a model-chosen value reaching the owner/tenant argument
   of a database read. This is the BOLA ownership model (#169) with a poisoned
   principal: the query IS ownership-fused, but the owner came from the model.
2. `guard_clause.py`'s new "principal" guard shape, which is what suppresses
   the safe version. It is a guard rather than a `pattern-sanitizers` entry on
   purpose -- comparing a value to the session principal transforms nothing, so
   modelling it as a sanitizer would repeat DEF-43.
3. The `llm_output` source origin in `EnrichmentPass`. Before this, an LLM
   completion was classified `model_output` at 0.1 confidence -- "almost
   certainly not attacker-influenced" -- which buried the entire
   `TNT-LLMOUT-*` family under the 0.7 default threshold.

Requires the Opengrep binary (skipped entirely if not installed, matching the
project's convention for tests that need a live scan).
"""

from __future__ import annotations

import ast
import tempfile
from pathlib import Path

import pytest

from rowan.analysis.guard_clause import _classify_guard_test
from rowan.config import ScanConfig
from rowan.core.findings import Category, ScanResult, Severity
from rowan.passes.authz import AuthzPass
from rowan.passes.base import ScanContext
from rowan.passes.enrichment import EnrichmentPass
from rowan.taint.opengrep_adapter import OpengrepAdapter

RULES_DIR = Path(__file__).parent.parent / "rules"

_adapter = OpengrepAdapter()
_needs_opengrep = pytest.mark.skipif(
    not _adapter.is_installed(),
    reason="Opengrep binary not installed; these tests need a live scan.",
)


def _scan(tmp_path: Path, source: str, rule_file: str, rule_id: str) -> list:
    (tmp_path / "target.py").write_text(source, encoding="utf-8")
    adapter = OpengrepAdapter()
    findings = adapter.scan_with_rules(
        tmp_path, [RULES_DIR / rule_file], languages=["python"]
    )
    return [f for f in findings if f.rule_id == rule_id]


def _scan_and_enrich(tmp_path: Path, source: str, rule_file: str, rule_id: str) -> list:
    findings = _scan(tmp_path, source, rule_file, rule_id)
    ctx = type("Ctx", (), {
        "target_path": tmp_path,
        "config": ScanConfig(target=tmp_path),
        "result": ScanResult(findings=findings),
        "metadata": {},
    })()
    EnrichmentPass().run(ctx)
    return [f for f in ctx.result.findings if f.rule_id == rule_id]


_MODEL = "class Order:\n    objects = None\n\n"


@_needs_opengrep
class TestTntAuthz001ModelChosenPrincipal:
    def test_tool_call_argument_as_principal_flagged(self, tmp_path):
        src = "import json\n" + _MODEL + (
            "def handler(tool_call):\n"
            "    args = json.loads(tool_call.function.arguments)\n"
            "    return Order.objects.filter(user_id=args['user_id'])\n"
        )
        assert _scan(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001"), (
            "an agent-chosen user_id must not silently scope a query"
        )

    def test_completion_content_as_principal_flagged(self, tmp_path):
        src = "import json, openai\nclient = openai.OpenAI()\n" + _MODEL + (
            "def handler(prompt):\n"
            "    completion = client.chat.completions.create(model='gpt-4', messages=prompt)\n"
            "    data = json.loads(completion.choices[0].message.content)\n"
            "    return Order.objects.filter(owner_id=data['owner'])\n"
        )
        assert _scan(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001")

    def test_session_principal_not_flagged(self, tmp_path):
        """The shape we are telling people to write."""
        src = "from flask import request\n" + _MODEL + (
            "def handler():\n"
            "    return Order.objects.filter(user_id=request.user.id)\n"
        )
        assert not _scan(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001")

    def test_non_principal_keyword_not_flagged(self, tmp_path):
        """`filter(status=model_value)` is an ordinary untrusted-input
        question, not an authorization one. Only owner-binding keywords are
        this rule's concern -- otherwise it would fire on every agent that
        builds a query."""
        src = "import json\n" + _MODEL + (
            "def handler(tool_call):\n"
            "    args = json.loads(tool_call.function.arguments)\n"
            "    return Order.objects.filter(status=args['status'])\n"
        )
        assert not _scan(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001")


@_needs_opengrep
class TestPrincipalGuardSuppression:
    """The safe versions, suppressed by dominance rather than by a sanitizer."""

    def test_equality_guard_against_principal_suppresses(self, tmp_path):
        src = "import json\nfrom flask import request\n" + _MODEL + (
            "def handler(tool_call):\n"
            "    args = json.loads(tool_call.function.arguments)\n"
            "    if args['user_id'] != request.user.id:\n"
            "        return 'forbidden', 403\n"
            "    return Order.objects.filter(user_id=args['user_id'])\n"
        )
        findings = _scan_and_enrich(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001")
        assert findings, "the finding is downgraded, never deleted"
        assert findings[0].metadata.get("guard_suppressed") == "principal"

    def test_policy_engine_guard_suppresses(self, tmp_path):
        src = "import json\nfrom flask import request\n" + _MODEL + (
            "def handler(tool_call, enforcer):\n"
            "    args = json.loads(tool_call.function.arguments)\n"
            "    if not enforcer.enforce(request.user.id, args['user_id'], 'read'):\n"
            "        return 'forbidden', 403\n"
            "    return Order.objects.filter(user_id=args['user_id'])\n"
        )
        findings = _scan_and_enrich(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001")
        assert findings[0].metadata.get("guard_suppressed") == "principal"

    def test_unguarded_is_not_suppressed(self, tmp_path):
        """Control: identical but for the guard."""
        src = "import json\n" + _MODEL + (
            "def handler(tool_call):\n"
            "    args = json.loads(tool_call.function.arguments)\n"
            "    return Order.objects.filter(user_id=args['user_id'])\n"
        )
        findings = _scan_and_enrich(tmp_path, src, "agent_taint.yaml", "TNT-AUTHZ-001")
        assert findings
        assert "guard_suppressed" not in findings[0].metadata


class TestPrincipalGuardShape:
    """Unit-level, no Opengrep needed."""

    @staticmethod
    def _test_expr(src: str) -> ast.expr:
        return ast.parse(src, mode="eval").body

    def test_comparison_against_principal_is_principal_kind(self):
        assert _classify_guard_test(
            self._test_expr("claimed != request.user.id"), "claimed"
        ) == "principal"

    def test_comparison_against_current_user_is_principal_kind(self):
        assert _classify_guard_test(
            self._test_expr("claimed == current_user.id"), "claimed"
        ) == "principal"

    def test_comparison_against_arbitrary_value_is_not_a_guard(self):
        """The narrowness that makes this sound: comparing to just anything is
        not an authorization check and must not suppress."""
        assert _classify_guard_test(
            self._test_expr("claimed != some_other_var"), "claimed"
        ) is None

    def test_policy_call_receiving_the_variable_is_principal_kind(self):
        assert _classify_guard_test(
            self._test_expr("not enforcer.enforce(actor, claimed, 'read')"), "claimed"
        ) == "principal"

    def test_policy_call_not_receiving_the_variable_is_not_a_guard(self):
        assert _classify_guard_test(
            self._test_expr("not enforcer.enforce(actor, other, 'read')"), "claimed"
        ) is None

    def test_unrelated_call_is_not_a_guard(self):
        """A call that merely receives the variable is not an authorization
        decision."""
        assert _classify_guard_test(
            self._test_expr("not check_format(claimed)"), "claimed"
        ) is None


class TestLlmOutputSourceOrigin:
    """`model_output` was scored 0.1 -- "almost certainly not attacker-
    influenced" -- which is the exact inverse of the LLM-output family's
    premise. These pin the corrected classification."""

    @staticmethod
    def _classify(snippet: str):
        return EnrichmentPass._classify_source_origin(snippet)

    @pytest.mark.parametrize("snippet", [
        "resp.choices[0].message.content",
        "chunk.choices[0].delta.content",
        "client.chat.completions.create(model='gpt-4')",
        "litellm.completion(model='gpt-4')",
        "client.messages.create(model='claude')",
        "tool_call.function.arguments",
        "llm.predict(prompt)",
        "agent.invoke(prompt)",
    ])
    def test_llm_shapes_are_high_confidence_untrusted(self, snippet):
        origin, conf = self._classify(snippet)
        assert origin == "llm_output"
        assert conf >= 0.9, "an LLM completion is an untrusted origin, not a safe one"

    @pytest.mark.parametrize("snippet", [
        "clf.predict(features)",
        "estimator.predict(X_test)",
    ])
    def test_classic_estimator_prediction_is_not_llm_output(self, snippet):
        """The distinction that keeps this narrow: a scikit-learn estimator's
        prediction is still an ordinary low-risk `model_output`."""
        origin, _ = self._classify(snippet)
        assert origin != "llm_output"


@_needs_opengrep
class TestShippedLlmOutputRulesNoLongerBuried:
    """Regression for the defect the origin fix closes. Before it, these two
    identical vulnerabilities were reported at different severities purely
    because of which SDK produced the completion -- and the clearer one was
    the one that got hidden."""

    _SRC = (
        "import subprocess\n"
        "{setup}\n"
        "def handler(prompt):\n"
        "    cmd = {completion}\n"
        "    subprocess.run(cmd, shell=True)\n"
    )

    def test_predict_style_completion_is_not_downgraded_to_info(self, tmp_path):
        src = self._SRC.format(setup="llm = object()", completion="llm.predict(prompt)")
        findings = _scan_and_enrich(tmp_path, src, "llm_output_taint.yaml", "TNT-LLMOUT-002")
        assert findings, "LLM completion reaching a shell sink must be reported"
        f = findings[0]
        assert f.metadata.get("source_origin") == "llm_output"
        assert f.severity != Severity.INFO, (
            "this was INFO/0.15 and tagged taint_unconfirmed before issue #185; "
            "the recommended CI gate hides INFO, so the RCE was invisible"
        )
        assert "taint_unconfirmed" not in f.metadata

    def test_client_style_completion_still_reported(self, tmp_path):
        src = self._SRC.format(
            setup="import openai\nclient = openai.OpenAI()",
            completion="client.chat.completions.create(model='m', messages=prompt).choices[0].message.content",
        )
        findings = _scan_and_enrich(tmp_path, src, "llm_output_taint.yaml", "TNT-LLMOUT-002")
        assert findings
        assert findings[0].severity != Severity.INFO


# ---------------------------------------------------------------------------
# AUTHZ-LLM-001: the guard is present, but the model made the decision.
# ---------------------------------------------------------------------------


def _make_project(files: dict[str, str]) -> Path:
    root = Path(tempfile.mkdtemp(prefix="rowan_llm_authz_"))
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


def _run_authz(root: Path, *, enable_authz: bool = True) -> ScanResult:
    config = ScanConfig(target=root, enable_authz=enable_authz)
    ctx = ScanContext(target_path=root, config=config, result=ScanResult())
    return AuthzPass().run(ctx)


def _llm_authz(result: ScanResult):
    return [f for f in result.findings if f.rule_id == "AUTHZ-LLM-001"]


_OPENAI_SETUP = "import json, openai\nclient = openai.OpenAI()\n\n"
_MODEL_CLASS = "class Document:\n    objects = None\n\n"


class TestAuthzLlm001DenyShape:
    """`if not <model-derived permission test>: raise/return/abort` --
    the early-return form, dominance-checked."""

    def test_early_return_deny_flagged(self, tmp_path):
        src = _OPENAI_SETUP + (
            "class PermissionDenied(Exception):\n    pass\n\n"
        ) + _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    decision = json.loads(verdict.choices[0].message.content)\n"
            "    if not decision['allowed']:\n"
            "        raise PermissionDenied\n"
            "    return Document.objects.get(id=doc_id)\n"
        )
        root = _make_project({"app.py": src})
        findings = _llm_authz(_run_authz(root))
        assert len(findings) == 1
        assert findings[0].metadata["guard_kind"] == "deny"
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == Category.AUTH

    def test_deny_body_that_falls_through_is_not_flagged(self, tmp_path):
        """The deny shape requires the negative branch to actually deny
        (raise/return/abort). A branch that merely logs and falls through
        isn't a guard at all -- BOLA's own absence detector is the relevant
        rule for that case, not this one."""
        src = _OPENAI_SETUP + _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    decision = json.loads(verdict.choices[0].message.content)\n"
            "    if not decision['allowed']:\n"
            "        print('denied, but continuing anyway')\n"
            "    return Document.objects.get(id=doc_id)\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root)) == []


class TestAuthzLlm001AllowShape:
    """`if <model-derived permission test>: <object access>` -- the
    positive-branch form, containment-checked."""

    def test_positive_branch_flagged(self, tmp_path):
        src = _OPENAI_SETUP + _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    decision = json.loads(verdict.choices[0].message.content)\n"
            "    if decision['allowed']:\n"
            "        return Document.objects.get(id=doc_id)\n"
            "    return 'forbidden', 403\n"
        )
        root = _make_project({"app.py": src})
        findings = _llm_authz(_run_authz(root))
        assert len(findings) == 1
        assert findings[0].metadata["guard_kind"] == "allow"

    def test_read_in_other_branch_not_flagged(self, tmp_path):
        """The object access must be inside the guarded (allow) branch, not
        the deny branch -- containment, not mere co-occurrence in the
        function."""
        src = _OPENAI_SETUP + _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    decision = json.loads(verdict.choices[0].message.content)\n"
            "    if decision['allowed']:\n"
            "        return 'ok'\n"
            "    return Document.objects.get(id=doc_id)\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root)) == []


class TestAuthzLlm001ToolCallArgument:
    """The guard test can be LLM-derived directly, with no intermediate
    assignment (`_model_derived_names` traces variables; the inline case is
    handled separately)."""

    def test_inline_tool_call_argument_flagged(self, tmp_path):
        src = _MODEL_CLASS + (
            "def dispatch(tool_call, doc_id):\n"
            "    if tool_call.function.arguments.get('can_access'):\n"
            "        return Document.objects.get(id=doc_id)\n"
            "    return None\n"
        )
        root = _make_project({"app.py": src})
        findings = _llm_authz(_run_authz(root))
        assert len(findings) == 1


class TestAuthzLlm001FalsePositiveAvoidance:
    """The cases that decide whether this rule is shippable."""

    def test_server_side_only_guard_not_flagged(self, tmp_path):
        """A guard built entirely from `request.user` -- no model involved
        at all -- must never fire. This is the ordinary, correct case."""
        src = "from flask import request\n" + _MODEL_CLASS + (
            "def handler(doc_id):\n"
            "    if not request.user.is_admin:\n"
            "        return 'forbidden', 403\n"
            "    return Document.objects.get(id=doc_id)\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root)) == []

    def test_llm_derived_but_not_permission_shaped_not_flagged(self, tmp_path):
        """A model-derived value branched on for a NON-authorization purpose
        must not fire -- this is the false positive that decides
        shippability per issue #185's own acceptance criteria."""
        src = _OPENAI_SETUP + _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    summary = json.loads(verdict.choices[0].message.content)\n"
            "    if summary['language'] == 'en':\n"
            "        return Document.objects.get(id=doc_id)\n"
            "    return None\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root)) == []

    def test_permission_shaped_but_not_llm_derived_not_flagged(self, tmp_path):
        """A permission-shaped guard built from a purely local computation --
        no model in the picture -- must not fire."""
        src = _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    decision = compute_local_policy(request)\n"
            "    if decision['allowed']:\n"
            "        return Document.objects.get(id=doc_id)\n"
            "    return None\n"
            "\n"
            "def compute_local_policy(request):\n"
            "    return {'allowed': True}\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root)) == []

    def test_claim_verified_against_principal_not_flagged(self, tmp_path):
        """The model's claim is compared against the actual session
        principal before use -- the model can't grant itself a role it
        doesn't already hold. Structurally distinct from `TNT-AUTHZ-001`'s
        sanitizer-avoidance reasoning (that's a taint rule; this is a
        presence-based AST rule), but the same principle: a claim that is
        cross-checked against server truth is not a bypass."""
        src = "from flask import request\n" + _OPENAI_SETUP + _MODEL_CLASS + (
            "def handler(doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    decision = json.loads(verdict.choices[0].message.content)\n"
            "    if decision['role'] != request.user.role:\n"
            "        return 'forbidden', 403\n"
            "    return Document.objects.get(id=doc_id)\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root)) == []

    def test_disabled_by_default_gate(self, tmp_path):
        src = _OPENAI_SETUP + _MODEL_CLASS + (
            "def handler(request, doc_id):\n"
            "    verdict = client.chat.completions.create(model='gpt-4', messages=[])\n"
            "    decision = json.loads(verdict.choices[0].message.content)\n"
            "    if decision['allowed']:\n"
            "        return Document.objects.get(id=doc_id)\n"
            "    return None\n"
        )
        root = _make_project({"app.py": src})
        assert _llm_authz(_run_authz(root, enable_authz=False)) == []

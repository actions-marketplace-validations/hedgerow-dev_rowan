"""Rule classification: vulnerability vs attack-surface inventory.

Some rules do not assert a vulnerability at all -- they catalogue *attack
surface*: an API is present (`from_pretrained`, an outbound HTTP call, a
dynamic import, an agent with subprocess access), or a reliability/cost smell
exists (an unbounded generation loop, a completion with no token cap). These
"presence signals" are useful as an inventory to review, but shipping them in
the same list as a proven SQL injection is precisely what drives Rowan's
false-positive rate: on real code they fire in the hundreds to thousands
(``config/thresholds.yaml`` documents ns-aiml-047 alone at 5,310 findings,
13% of all output), essentially none of them an actual bug.

This module names those rules explicitly so one taxonomy -- not a scatter of
per-rule suppressors -- decides what is a vulnerability finding and what is
inventory. The ``--actionable`` view hides inventory findings unless they
carry computed evidence (a taint flow proving attacker input actually reaches
the surface), while the full/default and ``--audit`` views still report them.

Deliberately conservative: a rule is listed here only when its match is a
presence/hygiene signal with no dataflow claim. Anything whose match is itself
the vulnerability (pickle.loads, eval, raw SQL interpolation, a hardcoded
secret) is NOT inventory. Trust-boundary judgement calls that could enable RCE
(e.g. trust_remote_code=True) are intentionally left OUT of the inventory set
pending review, so this never downgrades a genuine code-execution risk by
mistake.

The set is the migration target for the per-rule surface-signal handling
currently spread across ``config/thresholds.yaml`` (min_confidence gates) and
``passes/enrichment.py`` (the ``_suppress_*`` methods); moving that logic onto
this single classification is Phase 5 of the FP-remediation plan.
"""

from __future__ import annotations

import re

#: Rules that report attack-surface inventory / hygiene signals, not
#: vulnerabilities. Each entry is a documented presence signal; see the
#: rule's own message and ``config/thresholds.yaml`` for the volume it drives.
INVENTORY_RULES: frozenset[str] = frozenset({
    "ns-aiml-047",   # from_pretrained() without a pinned revision (supply-chain hygiene)
    "ns-aiml-048",   # dynamic import surface (import_module/__import__ present)
    "ns-aiml-076",   # LLM agent with shell/subprocess access (capability present)
    "NS-AIML-010",   # agent tool with system access (capability present)
    "NS-SSRF-001",   # outbound HTTP request present (Python surface signal)
    "NS-SSRF-102",   # outbound HTTP request present (Python surface signal)
    "NS-SSRF-103",   # outbound HTTP request present (Node.js surface signal)
    "RB-PATH-001",   # Ruby file-path API present, no user-control differentiation
    "ns-aiml-111",   # agent-memory write missing per-user scoping (presence signal)
    "ns-aiml-112",   # agent-memory read missing per-user scoping (presence signal)
    "ns-aiml-120",   # unbounded while-True generation loop (reliability, not security)
    "ns-aiml-121",   # completion call with no max_tokens/max_completion_tokens (cost)
})

#: Java/Go AI ports (BACKLOG.md JG-02) are named `tnt-<ja|go>-ai-<class>-NNN`.
#: These classes are presence signals (request reaches a system prompt or a
#: vector filter, an MCP server binds a network transport), not a dangerous
#: sink; every other class (sqli, exec, toolexec, ssrf, path, xss, spel,
#: deser, yaml, mcpcmd) is a vulnerability whose category, as for the Python
#: TNT-AIML-*/TNT-ML-* originals, decides the dangerous-sink handling.
_AI_PORT_INVENTORY_RE = re.compile(r"^tnt-(?:ja|go)-ai-(?:sysprompt|mcpbind|vectorq)-")


#: Rules whose match is itself a code-execution / RCE-enabling condition, but
#: whose category is not one the report views already treat as a dangerous sink
#: (e.g. `ai_ml`). The match is self-evident (the setting IS the risk, no
#: dataflow is claimed, like a hardcoded secret), so these are kept in every
#: view including --confirmed. Without this, trust_remote_code=True dropped out
#: of the actionable view even though the labeled corpus marks it a must-detect
#: regression vuln. Keep this set tiny and RCE-specific; a rule that only
#: *might* matter with attacker input belongs in a dataflow category, not here.
DANGEROUS_RULES: frozenset[str] = frozenset({
    "NS-AIML-001",   # trust_remote_code=True -> arbitrary code execution on model load
})


def is_dangerous_rule(rule_id: str) -> bool:
    """True if `rule_id`'s match is a self-evident code-execution risk that the
    report views must keep even though its category is not a dangerous-sink
    category (see `DANGEROUS_RULES`)."""
    return rule_id in DANGEROUS_RULES


def is_inventory_rule(rule_id: str) -> bool:
    """True if ``rule_id`` reports attack-surface inventory rather than a
    vulnerability. Used by the ``--actionable`` view (which hides inventory
    unless a taint flow backs it) and by reporters to label findings."""
    return rule_id in INVENTORY_RULES or bool(_AI_PORT_INVENTORY_RE.match(rule_id))


def rule_class(rule_id: str) -> str:
    """``"inventory"`` for surface/hygiene signals, ``"vulnerability"``
    otherwise. The default is ``"vulnerability"`` so a rule is only ever
    demoted by an explicit, reviewed decision to list it above."""
    return "inventory" if is_inventory_rule(rule_id) else "vulnerability"

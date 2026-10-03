"""Pure, inspectable construction of the ordered scan-pass plan."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from rowan.config import ScanConfig
from rowan.core.rules import NeuroScanRule
from rowan.passes.agent_flow import AgentFlowPass
from rowan.passes.ast_enrichment import ASTEnrichmentPass
from rowan.passes.authz import AuthzPass
from rowan.passes.base import PipelineStep
from rowan.passes.config_taint import ConfigTaintPass
from rowan.passes.cross_file import CrossFilePass
from rowan.passes.dormant_code import DormantCodePass
from rowan.passes.enrichment import EnrichmentPass
from rowan.passes.file_scan import FileScanPass
from rowan.passes.go_cross_file import GoCrossFilePass
from rowan.passes.instruction_smuggling import InstructionSmugglingPass
from rowan.passes.js_authz import JSAuthzPass
from rowan.passes.js_cross_file import JSCrossFilePass
from rowan.passes.mcp_config import MCPConfigScanPass
from rowan.passes.mcp_network_exposure import MCPNetworkExposurePass
from rowan.passes.mcp_sampling_approval import MCPSamplingApprovalPass
from rowan.passes.mcp_stored_content import MCPStoredContentPass
from rowan.passes.mcp_tool_metadata import MCPToolMetadataPass
from rowan.passes.membership_inference import MembershipInferencePass
from rowan.passes.mfv import ModelFileScanPass
from rowan.passes.model_extraction import ModelExtractionPass
from rowan.passes.multiagent import MultiAgentPass
from rowan.passes.pii_egress import PiiEgressPass
from rowan.passes.sca import SCAPass
from rowan.passes.serialization_scope import SerializationScopePass
from rowan.passes.sibling_gate import SiblingGatePass
from rowan.passes.taint import TaintPass
from rowan.passes.training_approval import TrainingApprovalPass
from rowan.passes.training_disclosure import TrainingDisclosurePass
from rowan.passes.web_security import WebSecurityPass


@dataclass(frozen=True)
class PlanRuntime:
    """Inputs needed only when a selected plan is instantiated for execution."""

    neuroscan_rules: list[NeuroScanRule]
    taint_rules_dir: Path


PassFactory = Callable[[PlanRuntime], PipelineStep]


# The pipeline runs passes in these stages, in this order (PL-12). file_scan
# owns discovery, the language cross-file passes consume detector findings,
# and the enrichment passes mutate the aggregate result.
EXECUTION_STAGES = ("discovery", "engine", "detection", "correlation", "enrichment")
_CORRELATION_PASSES = frozenset({"crossfile", "js_crossfile", "go_crossfile"})
_MUTATING_PASSES = frozenset({"ast_enrichment", "enrichment"})


def execution_stage(name: str) -> str:
    """The stage a pass runs in. Keep ``detection`` the default and the other
    stages narrow: a pass must be proven independent to run concurrently."""
    if name == "file_scan":
        return "discovery"
    if name == "taint":
        # Opengrep owns a bounded subprocess/batch budget. Isolate it until a
        # scan-wide token allocator can divide CPU across every engine.
        return "engine"
    if name in _CORRELATION_PASSES:
        return "correlation"
    if name in _MUTATING_PASSES:
        return "enrichment"
    return "detection"


@dataclass(frozen=True)
class PlannedPass:
    """One selected or explicitly disabled pipeline pass."""

    name: str
    selected: bool
    reason: str
    factory: PassFactory | None = None

    def as_dict(self) -> dict[str, str]:
        return {
            "name": self.name,
            "stage": execution_stage(self.name),
            "status": "selected" if self.selected else "explicitly_disabled",
            "reason": self.reason,
        }


@dataclass(frozen=True)
class ScanPlan:
    """Ordered execution plan plus the policy that produced it."""

    passes: tuple[PlannedPass, ...]
    effective_policy: dict[str, object]

    @property
    def selected(self) -> tuple[PlannedPass, ...]:
        return tuple(item for item in self.passes if item.selected)

    @property
    def disabled(self) -> tuple[PlannedPass, ...]:
        return tuple(item for item in self.passes if not item.selected)

    def in_execution_order(self) -> tuple[PlannedPass, ...]:
        """Passes sorted by stage, plan order within a stage."""
        return tuple(sorted(
            self.passes, key=lambda item: EXECUTION_STAGES.index(execution_stage(item.name))
        ))

    def instantiate(self, runtime: PlanRuntime) -> list[PipelineStep]:
        steps: list[PipelineStep] = []
        for item in self.selected:
            if item.factory is None:  # pragma: no cover - construction invariant
                raise RuntimeError(f"Selected pass has no factory: {item.name}")
            steps.append(item.factory(runtime))
        return steps

    def as_dict(self) -> dict[str, object]:
        return {
            "effective_policy": self.effective_policy,
            "selected_passes": [item.as_dict() for item in self.in_execution_order() if item.selected],
            "disabled_passes": [item.as_dict() for item in self.in_execution_order() if not item.selected],
        }


def build_scan_plan(config: ScanConfig) -> ScanPlan:
    """Resolve pass selection without reading source, loading rules, or running tools."""

    config.validate()
    planned: list[PlannedPass] = []
    legacy_neuroscan = config.legacy_neuroscan

    # Policies are deliberately capability contracts rather than opaque
    # performance knobs. Source analysis is local and deterministic; no
    # policy starts an LLM workflow, sends source to a remote service, or
    # probes a live target. SCA advisory resolution is the one documented
    # network capability of the comprehensive policies. "deep" adds the two
    # stable but higher-cost repository analyses without widening source or
    # live-target trust boundaries.
    policy_defaults: dict[str, dict[str, bool]] = {
        "default": {
            "sca": True,
            "taint_dataflow": True,
            "cross_file": True,
            "authz": False,
            "multiagent": False,
        },
        "fast": {
            "sca": False,
            "taint_dataflow": False,
            "cross_file": False,
            "authz": False,
            "multiagent": False,
        },
        "deep": {
            "sca": True,
            "taint_dataflow": True,
            "cross_file": True,
            "authz": True,
            "multiagent": True,
        },
    }[config.policy]

    def enabled(name: str, override: bool | None, disabled: bool = False) -> bool:
        """Resolve a policy capability, with explicit primitive flags winning."""
        if disabled:
            return False
        return policy_defaults[name] if override is None else override

    sca_enabled = enabled("sca", config.enable_sca, config.no_sca)
    # ScanConfig.validate() only knows the explicit --no-sca case; a policy
    # that leaves SCA off would otherwise write an SBOM/VEX with no
    # components and no warning, which reads downstream as a vetted
    # supply chain.
    if not sca_enabled and (config.vex_path or config.sbom_path):
        requested = ", ".join(
            flag for flag, value in (("--vex", config.vex_path), ("--sbom", config.sbom_path))
            if value
        )
        raise ValueError(
            f"{requested} requires dependency scanning, but the '{config.policy}' "
            "policy leaves SCA off; add --sca"
        )
    taint_dataflow = enabled("taint_dataflow", config.enable_taint, config.no_taint)
    cross_file_enabled = enabled("cross_file", config.enable_cross_file, config.no_cross_file)
    authz_enabled = enabled("authz", config.enable_authz)
    multiagent_enabled = enabled("multiagent", config.enable_multiagent)

    def add(
        name: str,
        factory: PassFactory,
        *,
        enabled: bool = True,
        selected_reason: str = "enabled by default",
        disabled_reason: str = "disabled by effective policy",
    ) -> None:
        planned.append(PlannedPass(
            name=name,
            selected=enabled,
            reason=selected_reason if enabled else disabled_reason,
            factory=factory if enabled else None,
        ))

    add(
        "file_scan",
        lambda runtime: FileScanPass(
            runtime.neuroscan_rules,
            legacy_neuroscan=legacy_neuroscan,
        ),
        selected_reason="required source discovery and pattern scan",
    )

    if not taint_dataflow and legacy_neuroscan:
        add(
            "taint",
            lambda runtime: TaintPass(runtime.taint_rules_dir),
            enabled=False,
            disabled_reason=(
                "no_taint with legacy_neuroscan"
                if config.no_taint
                else "policy disables dataflow with legacy_neuroscan"
            ),
        )
    else:
        regex_only = not taint_dataflow
        add(
            "taint",
            lambda runtime: TaintPass(
                runtime.taint_rules_dir,
                legacy_neuroscan=legacy_neuroscan,
                regex_only=regex_only,
            ),
            selected_reason=(
                "converted regex rules only; dataflow disabled by no_taint"
                if regex_only
                else "dataflow and converted regex analysis enabled"
            ),
        )

    add(
        "sca",
        lambda runtime: SCAPass(),
        enabled=sca_enabled,
        selected_reason="dependency analysis enabled",
        disabled_reason=("no_sca" if config.no_sca else "not selected by policy"),
    )

    cross_file: tuple[tuple[str, PassFactory], ...] = (
        ("sibling_gate", lambda runtime: SiblingGatePass()),
        ("crossfile", lambda runtime: CrossFilePass()),
        ("pii_egress", lambda runtime: PiiEgressPass()),
        ("training_disclosure", lambda runtime: TrainingDisclosurePass()),
        ("model_extraction", lambda runtime: ModelExtractionPass()),
        ("membership_inference", lambda runtime: MembershipInferencePass()),
        ("dormant-code", lambda runtime: DormantCodePass()),
        ("training-approval", lambda runtime: TrainingApprovalPass()),
        ("config-taint", lambda runtime: ConfigTaintPass()),
        ("js_crossfile", lambda runtime: JSCrossFilePass()),
        ("go_crossfile", lambda runtime: GoCrossFilePass()),
    )
    for name, factory in cross_file:
        add(
            name,
            factory,
            enabled=cross_file_enabled,
            selected_reason="repository-wide analysis enabled",
            disabled_reason=("no_cross_file" if config.no_cross_file else "not selected by policy"),
        )

    for name, factory in (
        ("authz", lambda runtime: AuthzPass()),
        ("js_authz", lambda runtime: JSAuthzPass()),
    ):
        add(
            name,
            factory,
            enabled=authz_enabled,
            selected_reason=("authz explicitly enabled" if config.enable_authz else "deep policy"),
            disabled_reason="authz not enabled",
        )

    for name, factory in (
        ("serialization-scope", lambda runtime: SerializationScopePass()),
        ("web-security", lambda runtime: WebSecurityPass()),
        ("agent-flow", lambda runtime: AgentFlowPass()),
    ):
        add(name, factory)

    add(
        "multiagent",
        lambda runtime: MultiAgentPass(),
        enabled=multiagent_enabled,
        selected_reason=("multiagent explicitly enabled" if config.enable_multiagent else "deep policy"),
        disabled_reason="multiagent not enabled",
    )

    for name, factory in (
        ("ast_enrichment", lambda runtime: ASTEnrichmentPass()),
        ("mfv", lambda runtime: ModelFileScanPass()),
        ("mcpconfig", lambda runtime: MCPConfigScanPass()),
        ("mcp-network-exposure", lambda runtime: MCPNetworkExposurePass()),
        ("mcp-sampling-approval", lambda runtime: MCPSamplingApprovalPass()),
        ("mcp_tool_metadata", lambda runtime: MCPToolMetadataPass()),
        ("mcp-stored-content", lambda runtime: MCPStoredContentPass()),
        ("instruction_smuggling", lambda runtime: InstructionSmugglingPass()),
        ("enrichment", lambda runtime: EnrichmentPass()),
    ):
        add(name, factory)

    effective_policy: dict[str, object] = {
        "name": config.policy,
        "contract": {
            "deterministic": True,
            "source_analysis": "local",
            "llm": False,
            "source_egress": False,
            "advisory_network": sca_enabled,
            "live_target": False,
        },
        "report_view": config.report_view,
        "languages": sorted(config.languages) or ["all"],
        "sca": sca_enabled,
        "taint_dataflow": taint_dataflow,
        "converted_regex": not legacy_neuroscan,
        "opengrep_required": not legacy_neuroscan,
        "cross_file": cross_file_enabled,
        "authz": authz_enabled,
        "multiagent": multiagent_enabled,
        "profile": config.profile,
        # Resource controls are part of the executable plan, not a hidden
        # runtime detail: users must be able to inspect the default cost cap
        # before a scan starts. Keep this path-free and resolved (None means
        # the network cap inherits the shared detector-worker budget).
        "resource_budget": {
            "detector_workers": config.concurrency,
            "network_requests": config.network_concurrency or config.concurrency,
            "network_source": (
                "explicit" if config.network_concurrency is not None else "concurrency"
            ),
        },
    }
    return ScanPlan(tuple(planned), effective_policy)

"""Free, zero-LLM-spend scope/cost preview for the hunt pipeline.

Runs exactly the static-scan (recon) stage `hunt` runs, then applies hunt's
own priority-filtering and batching logic (`HuntWorkflow._select_priority_findings`,
`_BATCH_SIZES`) to project how many LLM calls -- and roughly how many tokens --
a real `hunt` run against this target would make. Spends nothing: no network
call to any LLM backend is made.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from rowan.agents.workflow import (
    _BATCH_SIZES,
    _DISCOVERY_MAX_FILE_LINES,
    HuntWorkflow,
    resolve_hunt_scan_config,
)
from rowan.pipeline import ScanPipeline

# Rough chars-per-token ratio for English/code text -- a floor, not a tokenizer.
_CHARS_PER_TOKEN = 4

# hypothesize/verify system prompts run several hundred tokens each; counted
# once per batch (system prompt is sent with every call, not just the first).
_SYSTEM_PROMPT_TOKENS = 650

# Rough size of one hypothesis/verdict JSON object in the model's response.
_OUTPUT_TOKENS_PER_FINDING = 120

# _finding_with_context sends ~15 lines of code context on each side of the
# match, at a rough 80 chars/line -- this is what actually drives input cost,
# not the size of the repo itself (hunt never sends whole files).
_CONTEXT_CHARS_PER_FINDING = 15 * 2 * 80

# Historical rule of thumb from real hunt runs: roughly half to two-thirds of
# priority findings clear hypothesize as confirmed/likely and proceed to
# verify. Used as a rough projection, not a guarantee -- actual rate depends
# heavily on the target's false-positive density.
_VERIFY_SURVIVAL_RATE = 0.6

# Discovery (ADR-0004) is the one stage that sends whole files, so unlike
# every other stage its input cost is measured directly off disk rather than
# projected from a per-finding context window. One LLM call per candidate file.
#
# Claims per file that survive the provenance gate and reach the verify pass.
# A deliberately conservative placeholder: there is no run history to derive
# it from yet, and the estimate is a floor for scoping, not a bill. Revisit
# once DISC-6 has produced real numbers.
_DISCOVERY_CLAIMS_PER_FILE = 1.5
_DISCOVERY_OUTPUT_TOKENS_PER_CLAIM = 180  # richer JSON than a triage verdict


def _batch_count(n: int, batch_size: int) -> int:
    if n <= 0:
        return 0
    return (n + batch_size - 1) // batch_size


@dataclass
class HuntEstimate:
    target: Path
    files_scanned: int
    total_findings: int
    priority_findings: int
    aiml_findings: int
    generic_findings: int
    hypothesize_batches: int
    verify_candidates_estimate: int
    verify_batches_estimate: int
    input_tokens_estimate: int
    output_tokens_estimate: int
    scan_errors: list[str] = field(default_factory=list)
    # Discovery stage (ADR-0004); all zero unless discover=True.
    discover: bool = False
    discover_files: int = 0
    discover_calls: int = 0

    def render(self) -> str:
        lines = [
            f"scope estimate for {self.target}",
            f"  files scanned          : {self.files_scanned}",
            f"  static findings        : {self.total_findings}",
            f"  priority findings      : {self.priority_findings} "
            f"({self.aiml_findings} AI/ML, {self.generic_findings} generic)",
            f"  hypothesize batches    : {self.hypothesize_batches}",
            f"  verify candidates (est): {self.verify_candidates_estimate} "
            f"(assumes ~{int(_VERIFY_SURVIVAL_RATE * 100)}% of priority findings "
            "clear hypothesize as confirmed/likely)",
            f"  verify batches (est)   : {self.verify_batches_estimate}",
        ]
        if self.discover:
            lines += [
                f"  discover files         : {self.discover_files} "
                f"(whole-file context, capped at {_DISCOVERY_MAX_FILE_LINES} lines each)",
                f"  discover calls (est)   : {self.discover_calls} "
                "(one per file, plus verification of what it finds)",
            ]
        lines += [
            f"  ~input tokens          : {self.input_tokens_estimate:,} "
            "(rough: code context chars/4 + per-batch prompt overhead)",
            f"  ~output tokens         : {self.output_tokens_estimate:,} "
            f"(rough: ~{_OUTPUT_TOKENS_PER_FINDING} tokens per JSON hypothesis/verdict)",
            "  note: real usage depends on the backend's tokenizer, code context",
            "  density, and how many findings actually survive triage. This is a",
            "  floor for scoping, not a bill -- deepdive/report/webexploit calls",
            "  add more on top and aren't modeled here.",
        ]
        if self.discover:
            lines.append(
                "  note: discover file count is a floor -- it omits this run's "
                "deep-dive\n  targets (they don't exist until hypothesize runs) "
                "and sink-only files."
            )
        if self.scan_errors:
            lines.append(f"  scan errors             : {len(self.scan_errors)} (see -v for detail)")
        return "\n".join(lines)


def estimate_hunt(
    target: Path,
    languages: list[str] | None = None,
    no_sca: bool = False,
    backend: str = "deepseek",
    discover: bool = False,
    project_config: bool = True,
) -> HuntEstimate:
    """Run hunt's recon stage only and project the LLM cost of a full run.

    This is the same static pipeline `hunt` itself runs first -- so the
    estimate reflects this exact target's real finding density, not a blind
    bytes-in-the-repo heuristic. No LLM backend is contacted.
    """
    # Mirrors the CLI `hunt` command's own config construction exactly (no_taint
    # is always False -- hunt's recon always runs taint analysis by design) so
    # the estimate reflects what a real `hunt` invocation will actually scan.
    config = resolve_hunt_scan_config(
        target,
        languages=languages,
        no_sca=no_sca,
        no_taint=False,
        project_config=project_config,
    )

    pipeline = ScanPipeline(config)
    result = pipeline.run()

    priority = HuntWorkflow._select_priority_findings(result.findings)
    aiml = [f for f in priority if HuntWorkflow._is_aiml_finding(f)]
    generic = [f for f in priority if not HuntWorkflow._is_aiml_finding(f)]

    batch_size = _BATCH_SIZES.get(backend, 10)
    hyp_batches = _batch_count(len(aiml), batch_size) + _batch_count(len(generic), batch_size)

    verify_estimate = round(len(priority) * _VERIFY_SURVIVAL_RATE)
    verify_batches = _batch_count(verify_estimate, batch_size)

    input_tokens = (
        (len(priority) * _CONTEXT_CHARS_PER_FINDING // _CHARS_PER_TOKEN)
        + (hyp_batches + verify_batches) * _SYSTEM_PROMPT_TOKENS
    )
    output_tokens = (len(priority) + verify_estimate) * _OUTPUT_TOKENS_PER_FINDING

    discover_files = 0
    discover_calls = 0
    if discover:
        # Same selection logic the real stage uses, minus the deep-dive
        # targets (which don't exist until hypothesize has run) and sinks
        # (whose files are almost always already in the priority set, since
        # sinks are themselves derived from findings). Documented as a floor.
        candidates = HuntWorkflow._discovery_files_from_surface(
            target, result.findings, []
        )
        discover_files = len(candidates)

        # Unlike every other stage, this one's input cost is measurable
        # directly: the files are right there on disk. Measure rather than
        # guess, capping each at what `_discovery_file_payload` would send.
        discover_chars = 0
        for path in candidates:
            try:
                file_lines = path.read_text(encoding="utf-8", errors="replace").split("\n")
            except OSError:
                continue
            discover_chars += sum(len(line) + 1 for line in file_lines[:_DISCOVERY_MAX_FILE_LINES])

        discover_claims = round(discover_files * _DISCOVERY_CLAIMS_PER_FILE)
        discover_verify_batches = _batch_count(discover_claims, batch_size)
        discover_calls = discover_files + discover_verify_batches

        input_tokens += (
            (discover_chars // _CHARS_PER_TOKEN)
            + (discover_files + discover_verify_batches) * _SYSTEM_PROMPT_TOKENS
        )
        output_tokens += discover_claims * _DISCOVERY_OUTPUT_TOKENS_PER_CLAIM * 2

    return HuntEstimate(
        target=target,
        files_scanned=result.files_scanned,
        total_findings=len(result.findings),
        priority_findings=len(priority),
        aiml_findings=len(aiml),
        generic_findings=len(generic),
        hypothesize_batches=hyp_batches,
        verify_candidates_estimate=verify_estimate,
        verify_batches_estimate=verify_batches,
        input_tokens_estimate=input_tokens,
        output_tokens_estimate=output_tokens,
        scan_errors=list(result.errors),
        discover=discover,
        discover_files=discover_files,
        discover_calls=discover_calls,
    )

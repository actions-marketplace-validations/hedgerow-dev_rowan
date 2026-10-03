# vuln_app corpus: labeled ground-truth vulnerable application

This corpus scores per-vulnerability recall against a **real, purpose-built,
answer-key-labeled** vulnerable application, and runs Semgrep over the same app
for a head-to-head comparison. Unlike `vuln_cases/` (isolated one-liner
snippets), this exercises the whole pipeline (taint, cross-file, enrichment)
against non-obvious vulnerabilities embedded in a plausible codebase, which is
where the meaningful gaps vs. general-purpose SAST show up.

## The app

The reference target is **ModelForge** (a self-hosted MLOps platform: model
registry, dataset ingestion, inference service, LLM assistant; Flask + SQLite),
seeded with ~19 planted vulnerabilities spanning the classes commonly reported
against real ML/AI open source (unsafe model deserialization, SSRF, path/zip
traversal, SQL/command injection, SSTI, IDOR, insecure config, and
LLM prompt-injection / agent tool abuse). Its own `benchmarks/ground_truth.yaml`
is the answer key (source, sink, taint path, and the "sanitizer traps" per vuln).

The app is **not committed to this repo** (it's a separate project). Point the
harness at a local checkout:

```bash
export ROWAN_VULN_APP_PATH=/path/to/modelforge
uv run python scripts/benchmark.py --corpus vuln_app            # + Semgrep head-to-head
uv run python scripts/benchmark.py --corpus vuln_app --no-semgrep
```

If `ROWAN_VULN_APP_PATH` is unset (or the app has no
`benchmarks/ground_truth.yaml`), the corpus is skipped cleanly.

## Scoring

A vulnerability counts as **detected** only if a finding (a) lands in the
ground-truth *sink file* within `VULN_APP_SINK_WINDOW` lines of the sink
line-hint, **and** (b) is *class-consistent*: its identity (category + rule id
+ message, or Semgrep's check-id + message) contains a keyword mapping to the
vuln's CWE. Proximity alone is deliberately **not** enough: an unrelated finding
landing near the sink line must not be credited. CWEs with no detector class
(CWE-639 IDOR, CWE-915 mass-assignment, both absence-of-check logic bugs) stay honest
MISSes for every pattern/taint tool. The same scoring is applied identically to
Semgrep so the head-to-head is apples-to-apples.

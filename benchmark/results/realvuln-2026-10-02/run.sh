#!/usr/bin/env bash
# RealVuln static scan with Rowan: --no-sca --audit, cross-file on.
# Usage: REALVULN_DIR=/path/to/Real-Vuln-Benchmark ./run.sh
set -uo pipefail
BENCH="${REALVULN_DIR:?set REALVULN_DIR to a Real-Vuln-Benchmark checkout}"
ROWAN="${ROWAN:-rowan}"
SLUG=rowan-v0.3.0
LOG=$BENCH/reports/$SLUG-run.log
: > "$LOG"
scan_one() {
  local repo_path="$1" repo out
  repo="$(basename "$repo_path")"; out="$BENCH/scan-results/$repo/$SLUG"; mkdir -p "$out"
  ( cd "$repo_path" && perl -e 'alarm shift; exec @ARGV' 900 \
      "$ROWAN" scan . --no-sca --audit --format json --output "$out/results.json" ) \
      > "$out/scan.log" 2>&1 && echo "ok   $repo" >> "$LOG" || echo "WARN $repo (exit $?)" >> "$LOG"
}
export -f scan_one; export BENCH ROWAN SLUG LOG
echo "start $(date)" >> "$LOG"
printf '%s\n' "$BENCH"/repos/*/ | xargs -P 2 -I{} bash -c 'scan_one "$@"' _ {}
echo "done $(date)" >> "$LOG"

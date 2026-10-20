#!/usr/bin/env bash
# Usage: cov-crate-gates.sh <min-percent> <crate>...
# Fails when a crate's line coverage is below the threshold. Crates whose
# source has no code yet (empty lib) are skipped.
set -euo pipefail
min="$1"; shift
json="$(cargo llvm-cov report --json --summary-only)"
for crate in "$@"; do
  dir="crates/${crate}/src/"
  read -r count covered < <(jq -r --arg d "$dir" '
    [.data[0].files[] | select(.filename | contains($d)) | .summary.lines]
    | "\(map(.count) | add // 0) \(map(.covered) | add // 0)"' <<<"$json")
  if [ "$count" -eq 0 ]; then echo "${crate}: no instrumented lines, skipped"; continue; fi
  pct=$(( covered * 100 / count ))
  echo "${crate}: ${pct}% lines (min ${min}%)"
  if [ "$pct" -lt "$min" ]; then exit 1; fi
done

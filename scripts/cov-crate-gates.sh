#!/usr/bin/env bash
# Usage: cov-crate-gates.sh <overall-min> <default-crate-min> [<crate>=<min>]...
# Reads the last `cargo llvm-cov` run (`cargo llvm-cov report --json`), prints a per-crate line
# coverage table and fails when the workspace total is below <overall-min>, or a crate is below its
# floor (<default-crate-min>, or the <crate>=<min> override). Crates with no instrumented lines are
# skipped. Percentages are exact (not rounded up): 89.99% fails a 90 gate.
set -euo pipefail
overall_min="$1"; default_min="$2"; shift 2
declare -A floor=()
for o in "$@"; do floor["${o%%=*}"]="${o#*=}"; done

json="$(cargo llvm-cov report --json --summary-only)"
fail=0
printf '%-16s %8s %8s %8s %6s\n' crate lines covered percent min
while read -r crate count covered; do
  min="${floor[$crate]:-$default_min}"
  if [ "$count" -eq 0 ]; then printf '%-16s %8s\n' "$crate" "no code, skipped"; continue; fi
  pct="$(awk -v c="$covered" -v n="$count" 'BEGIN{printf "%.2f", 100*c/n}')"
  verdict=ok
  if awk -v p="$pct" -v m="$min" 'BEGIN{exit !(p < m)}'; then verdict=FAIL; fail=1; fi
  printf '%-16s %8d %8d %7s%% %5s%% %s\n' "$crate" "$count" "$covered" "$pct" "$min" "$verdict"
done < <(jq -r '
  [.data[0].files[]
   | select(.filename | test("/crates/[^/]+/src/"))
   | {crate: (.filename | capture("/crates/(?<c>[^/]+)/src/").c), l: .summary.lines}]
  | group_by(.crate)[]
  | "\(.[0].crate) \(map(.l.count) | add) \(map(.l.covered) | add)"' <<<"$json")

read -r count covered < <(jq -r '.data[0].totals.lines | "\(.count) \(.covered)"' <<<"$json")
pct="$(awk -v c="$covered" -v n="$count" 'BEGIN{printf "%.2f", 100*c/n}')"
verdict=ok
if awk -v p="$pct" -v m="$overall_min" 'BEGIN{exit !(p < m)}'; then verdict=FAIL; fail=1; fi
printf '%-16s %8d %8d %7s%% %5s%% %s\n' workspace "$count" "$covered" "$pct" "$overall_min" "$verdict"
exit "$fail"

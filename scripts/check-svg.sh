#!/usr/bin/env bash
# Validate branding SVGs: parsed as XML (no script, foreignObject, image, style, on* handlers,
# external href or url(), DOCTYPE/ENTITY), viewBox set, size budget.
# `check-svg.sh --self-test` proves every negative fixture is rejected and the positive one passes.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
check() { python3 -I "$here/check-svg.py" "$1"; }
max=20480

if [ "${1:-}" = "--self-test" ]; then
  fail=0
  check "$here/check-svg-fixtures/good.svg" >/dev/null || { echo "FAIL good fixture rejected"; fail=1; }
  for f in "$here"/check-svg-fixtures/bad/*.svg; do
    if check "$f" >/dev/null; then echo "FAIL not rejected: $f"; fail=1; fi
  done
  [ "$fail" -eq 0 ] && echo "check-svg self-test ok"
  exit "$fail"
fi

fail=0
mapfile -t files < <(find "${1:-branding}" -name '*.svg' | sort)
if [ "${#files[@]}" -eq 0 ]; then echo "no SVG files found" >&2; exit 1; fi
for f in "${files[@]}"; do
  if reasons=$(check "$f"); then :; else
    while IFS= read -r r; do echo "FAIL $r: $f"; done <<<"$reasons"
    fail=1
  fi
  size=$(wc -c <"$f")
  [ "$size" -lt "$max" ] || { echo "FAIL ${size} bytes >= ${max}: $f"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "check-svg: ${#files[@]} files ok"
exit "$fail"

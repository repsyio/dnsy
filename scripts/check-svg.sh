#!/usr/bin/env bash
# Validate branding SVGs: well-formed XML, viewBox set, no external refs, size budget.
set -euo pipefail
max=20480
fail=0
mapfile -t files < <(find "${1:-branding}" -name '*.svg' | sort)
if [ "${#files[@]}" -eq 0 ]; then echo "no SVG files found" >&2; exit 1; fi
for f in "${files[@]}"; do
  if command -v xmllint >/dev/null 2>&1; then
    xmllint --noout "$f" || { echo "FAIL not well-formed: $f"; fail=1; continue; }
  else
    python3 -I -c 'import sys,xml.dom.minidom as m; m.parse(sys.argv[1])' "$f" 2>/dev/null \
      || { echo "FAIL not well-formed: $f"; fail=1; continue; }
  fi
  grep -q 'viewBox="' "$f" || { echo "FAIL no viewBox: $f"; fail=1; }
  if grep -E -q '(href|src)=|url\((https?:|//)|@import|<image|<script|<foreignObject' "$f"; then
    echo "FAIL external reference or script: $f"; fail=1
  fi
  size=$(wc -c <"$f")
  [ "$size" -lt "$max" ] || { echo "FAIL ${size} bytes >= ${max}: $f"; fail=1; }
done
[ "$fail" -eq 0 ] && echo "check-svg: ${#files[@]} files ok"
exit "$fail"

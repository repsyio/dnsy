#!/usr/bin/env bash
# Fails if a binary needs a glibc symbol version newer than the floor (default 2.28, the manylinux_2_28
# containers the gnu release targets build in; see docs/book/src/release.md).
# Usage: scripts/check-glibc-floor.sh <binary> [max-version]
set -euo pipefail

bin="${1:?usage: check-glibc-floor.sh <binary> [max-version]}"
max="${2:-2.28}"

versions="$(objdump -T "$bin" | grep -o 'GLIBC_[0-9][0-9.]*' | sed 's/^GLIBC_//' | sort -uV || true)"
if [ -z "$versions" ]; then
  echo "no GLIBC_ symbol versions in $bin (static or non-glibc binary): nothing to check"
  exit 0
fi

highest="$(printf '%s\n' "$versions" | tail -n 1)"
echo "highest GLIBC symbol version in $bin: $highest (floor $max)"
if [ "$(printf '%s\n%s\n' "$highest" "$max" | sort -V | tail -n 1)" != "$max" ]; then
  echo "error: $bin needs glibc $highest, above the $max floor; offending symbols:" >&2
  objdump -T "$bin" | grep -E "GLIBC_(${highest//./\\.})\b" | head -n 10 >&2 || true
  exit 1
fi

#!/usr/bin/env bash
# Merges the Linux packages into a release's sha256.sum.
#
#   update-sha256sum.sh <sums-file> <package-dir>
#
# cargo-dist writes sha256.sum before package-linux.yml builds the .deb and .rpm files, so the sum
# does not list them. This adds one line per dnsy_*.deb and dnsy-*.rpm in <package-dir>, in dist's
# format (`<sha256> *<filename>`), replaces any existing line for the same filename (a re-run with a
# new hash does not leave two lines), keeps every other line untouched and sorts by filename like
# dist. It rewrites <sums-file> in place. It fails, changing nothing, when <sums-file> is missing or
# empty (it must come from the release: never create a sum that lists only the packages) or when
# <package-dir> holds no package.
set -euo pipefail
export LC_ALL=C

if [ "$#" -ne 2 ]; then
  echo "usage: $0 <sums-file> <package-dir>" >&2
  exit 2
fi
sums=$1
dir=$2

if [ ! -s "$sums" ]; then
  echo "error: $sums is missing or empty; the release must already have the sha256.sum written by cargo-dist (refusing to create one that lists only packages)" >&2
  exit 1
fi
if [ ! -d "$dir" ]; then
  echo "error: package directory $dir does not exist" >&2
  exit 1
fi

shopt -s nullglob
packages=("$dir"/dnsy_*.deb "$dir"/dnsy-*.rpm)
if [ "${#packages[@]}" -eq 0 ]; then
  echo "error: no dnsy_*.deb or dnsy-*.rpm in $dir" >&2
  exit 1
fi

tmp=$(mktemp)
trap 'rm -f "$tmp" "$tmp.new"' EXIT

# Lines to add, as `<name><TAB><hash> *<name>`.
new=()
for p in "${packages[@]}"; do
  name=${p##*/}
  hash=$(sha256sum "$p")
  hash=${hash%% *}
  new+=("$name"$'\t'"$hash *$name")
done

# Existing lines, as `<name><TAB><line>`, minus the ones the packages replace.
# A line is `<hash> <mode char><name>` where the mode char is `*` (binary) or a space (text).
{
  while IFS= read -r line || [ -n "$line" ]; do
    [ -n "$line" ] || continue
    name=${line#* }
    name=${name:1}
    printf '%s\t%s\n' "$name" "$line"
  done < "$sums"
} > "$tmp"

{
  for n in "${new[@]}"; do printf '%s\n' "$n"; done
  while IFS=$'\t' read -r name line; do
    replaced=0
    for n in "${new[@]}"; do
      if [ "${n%%$'\t'*}" = "$name" ]; then replaced=1; break; fi
    done
    [ "$replaced" -eq 1 ] || printf '%s\t%s\n' "$name" "$line"
  done < "$tmp"
} | sort -t $'\t' -k1,1 | cut -f2- > "$tmp.new"

cp "$tmp.new" "$sums"
echo "updated $sums: ${#packages[@]} package line(s), $(wc -l < "$sums") line(s) in total"

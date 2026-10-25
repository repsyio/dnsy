#!/usr/bin/env bash
# Builds the .deb and .rpm packages (amd64 and arm64) from the release archives, with nfpm.
# Nothing is compiled: each package holds the dnsy binary from dnsy-<triple>.tar.xz.
# Usage: scripts/package-linux.sh <version> <archive-dir> <out-dir>
#   version      without a leading "v" (0.1.0, 0.2.0-rc.1)
#   archive-dir  holds dnsy-x86_64-unknown-linux-gnu.tar.xz and dnsy-aarch64-unknown-linux-gnu.tar.xz
#   out-dir      receives dnsy_<ver>_<arch>.deb, dnsy-<ver>-1.<rpmarch>.rpm and a .sha256 for each
# Needs nfpm on PATH (scripts/install-nfpm.sh).
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <version> <archive-dir> <out-dir>" >&2; exit 2; }
version=$1
archives=$(cd "$2" && pwd)
mkdir -p "$3"
out=$(cd "$3" && pwd)
cd "$(dirname "$0")/.."

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for pair in x86_64-unknown-linux-gnu:amd64 aarch64-unknown-linux-gnu:arm64; do
  triple=${pair%%:*}
  arch=${pair##*:}
  tarball=$archives/dnsy-$triple.tar.xz
  [ -f "$tarball" ] || { echo "missing $tarball" >&2; exit 1; }
  mkdir -p "$work/$triple"
  tar -xJf "$tarball" -C "$work/$triple"
  bin=$work/$triple/dnsy-$triple/dnsy
  [ -f "$bin" ] || { echo "$tarball has no dnsy-$triple/dnsy" >&2; exit 1; }
  for format in deb rpm; do
    DNSY_ARCH=$arch DNSY_VERSION=$version DNSY_BIN=$bin \
      nfpm package --config packaging/nfpm.yaml --packager "$format" --target "$out/"
  done
done

(
  cd "$out"
  shopt -s nullglob
  files=(dnsy_*.deb dnsy-*.rpm)
  [ ${#files[@]} -eq 4 ] || { echo "expected 4 packages, found ${#files[@]}: ${files[*]}" >&2; exit 1; }
  for f in "${files[@]}"; do sha256sum "$f" > "$f.sha256"; done
)

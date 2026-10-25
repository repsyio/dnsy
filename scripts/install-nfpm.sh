#!/usr/bin/env bash
# Installs the pinned nfpm release into a directory (default: ./.nfpm-bin) after checking the
# tarball against the sha256 from that release's checksums.txt. Never pipes a download to a shell.
# Usage: scripts/install-nfpm.sh [dir]   (prints nothing but errors; add dir to PATH afterwards)
set -euo pipefail

version=2.48.0
# From https://github.com/goreleaser/nfpm/releases/download/v2.48.0/checksums.txt
sha_x86_64=6d7f9a28b2f397934403950fcbba83f598b08d02edbe79a0815b3b4897341750
sha_arm64=a9a75213763783b7669719e505474c748c5ad7dc66591a195619deb50f85c2f4

dir=${1:-.nfpm-bin}
case "$(uname -m)" in
  x86_64) arch=x86_64; want=$sha_x86_64 ;;
  aarch64 | arm64) arch=arm64; want=$sha_arm64 ;;
  *) echo "unsupported machine $(uname -m)" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
file=nfpm_${version}_Linux_${arch}.tar.gz
curl --proto '=https' --tlsv1.2 -fsSL -o "$tmp/$file" \
  "https://github.com/goreleaser/nfpm/releases/download/v${version}/${file}"
echo "$want  $tmp/$file" | sha256sum -c - >&2
mkdir -p "$dir"
tar -xzf "$tmp/$file" -C "$dir" nfpm
"$dir/nfpm" --version >&2

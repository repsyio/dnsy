#!/usr/bin/env bash
# Regenerates .github/workflows/release.yml with cargo-dist, then hardens it:
#   * every action is pinned by full commit SHA (dist emits floating tags),
#   * workflow-level permissions are `contents: read`; only the `host` job (creates the GitHub
#     Release) gets `contents: write`.
# dist-workspace.toml sets allow-dirty = ["ci"] so `dist plan` accepts the hardened file.
# Usage: scripts/generate-release-workflow.sh   (needs `dist` 0.33.1 on PATH)
set -euo pipefail
cd "$(dirname "$0")/.."

want="cargo-dist 0.33.1"
[ "$(dist --version)" = "$want" ] || { echo "need $want, got $(dist --version)" >&2; exit 1; }

# allow-dirty must be off while generating so dist rewrites the file from its template.
sed -i '/^allow-dirty = /d' dist-workspace.toml
dist generate
sed -i 's|^# Build prerequisites|allow-dirty = ["ci"]\n# Build prerequisites|' dist-workspace.toml

python3 - <<'PY'
import re
p = ".github/workflows/release.yml"
s = open(p).read()
pins = {
    "actions/checkout@v6": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1",
    "actions/upload-artifact@v7": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9 # v7.0.2",
    "actions/download-artifact@v8": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333 # v8.0.2",
}
for old, new in pins.items():
    assert old in s, old
    s = s.replace(old, new)
s = s.replace('uses: "pnpm/action-setup@ea17c68df8912ef543352723c149a84f56e3d413"',
              "uses: pnpm/action-setup@ea17c68df8912ef543352723c149a84f56e3d413 # v6.1.0")
s = s.replace('uses: "actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1"',
              "uses: actions/setup-node@949feb2413d6458794dcd2491c4babbbce0c15c1 # v7.1.0")
assert not re.search(r"uses: [^\n]*@v\d", s), "unpinned action left"
s = s.replace('permissions:\n  "contents": "write"', 'permissions:\n  contents: read', 1)
s = s.replace('  host:\n    needs:', '  host:\n    permissions:\n      contents: write\n    needs:', 1)
s = s.replace("  custom-release-verify:\n", "  custom-release-verify:\n    permissions:\n      contents: read\n", 1)
open(p, "w").write(s)
PY

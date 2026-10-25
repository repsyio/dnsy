#!/usr/bin/env bash
# Tests for scripts/update-sha256sum.sh: adding lines, an idempotent re-run, a replaced hash,
# a missing sha256.sum, and the `~` of prerelease versions in file names.
set -u
script=$(cd "$(dirname "$0")/../.." && pwd)/scripts/update-sha256sum.sh
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
failures=0
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }
hash_of() { local h; h=$(sha256sum "$1"); echo "${h%% *}"; }

# new_case <name>: a fresh dir with archives in dist's format and a packages dir.
new_case() {
  C=$T/$1; rm -rf "$C"; mkdir -p "$C/pkg"
  printf 'a' > "$C/dnsy-x86_64-unknown-linux-gnu.tar.xz"
  printf 'b' > "$C/source.tar.gz"
  { echo "$(hash_of "$C/dnsy-x86_64-unknown-linux-gnu.tar.xz") *dnsy-x86_64-unknown-linux-gnu.tar.xz"
    echo "$(hash_of "$C/source.tar.gz") *source.tar.gz"; } > "$C/sha256.sum"
}
mkpkgs() { # <version>
  printf 'deb-amd64-%s' "$1" > "$C/pkg/dnsy_$1_amd64.deb"
  printf 'deb-arm64-%s' "$1" > "$C/pkg/dnsy_$1_arm64.deb"
  printf 'rpm-x86-%s' "$1" > "$C/pkg/dnsy-${1/\~/_}-1.x86_64.rpm"
  printf 'rpm-arm-%s' "$1" > "$C/pkg/dnsy-${1/\~/_}-1.aarch64.rpm"
}
run() { bash "$script" "$C/sha256.sum" "$C/pkg" > "$C/out" 2>&1; echo $? > "$C/rc"; }
rc() { cat "$C/rc"; }
names() { sed 's/^[0-9a-f]* [ *]//' "$C/sha256.sum"; }

# 1. adds the lines, dist's format, sorted by name, existing lines untouched, all verify.
new_case add; mkpkgs 0.1.0; cp "$C"/pkg/* "$C"/ ; run
[ "$(rc)" = 0 ] || fail "add: exit $(rc): $(cat "$C/out")"
want="dnsy-0.1.0-1.aarch64.rpm
dnsy-0.1.0-1.x86_64.rpm
dnsy-x86_64-unknown-linux-gnu.tar.xz
dnsy_0.1.0_amd64.deb
dnsy_0.1.0_arm64.deb
source.tar.gz"
[ "$(names)" = "$want" ] || fail "add: names were: $(names)"
grep -Eq '^[0-9a-f]{64} \*dnsy_0\.1\.0_amd64\.deb$' "$C/sha256.sum" || fail "add: wrong line format"
grep -qF "$(hash_of "$C/source.tar.gz") *source.tar.gz" "$C/sha256.sum" || fail "add: old line changed"
(cd "$C" && sha256sum -c sha256.sum > /dev/null 2>&1) || fail "add: sha256sum -c failed"

# 2. a re-run changes nothing.
cp "$C/sha256.sum" "$C/first"; run
[ "$(rc)" = 0 ] || fail "rerun: exit $(rc)"
cmp -s "$C/first" "$C/sha256.sum" || fail "rerun: file changed"
[ "$(wc -l < "$C/sha256.sum")" = 6 ] || fail "rerun: duplicated lines"

# 3. a rebuilt package with a new hash replaces its line.
printf 'rebuilt' > "$C/pkg/dnsy_0.1.0_amd64.deb"; run
[ "$(rc)" = 0 ] || fail "replace: exit $(rc)"
[ "$(wc -l < "$C/sha256.sum")" = 6 ] || fail "replace: line count changed"
[ "$(grep -c 'dnsy_0.1.0_amd64.deb' "$C/sha256.sum")" = 1 ] || fail "replace: duplicate line"
grep -qF "$(hash_of "$C/pkg/dnsy_0.1.0_amd64.deb") *dnsy_0.1.0_amd64.deb" "$C/sha256.sum" || fail "replace: hash not updated"

# 4. missing sha256.sum is an error with a clear message, and nothing is created.
new_case missing; mkpkgs 0.1.0; rm "$C/sha256.sum"; run
[ "$(rc)" != 0 ] || fail "missing: succeeded"
grep -q 'missing or empty' "$C/out" || fail "missing: message was: $(cat "$C/out")"
[ ! -e "$C/sha256.sum" ] || fail "missing: created a sum file"
new_case empty; mkpkgs 0.1.0; : > "$C/sha256.sum"; run
[ "$(rc)" != 0 ] || fail "empty: succeeded"

# 5. no packages is an error and leaves the sum alone.
new_case nopkg; cp "$C/sha256.sum" "$C/orig"; run
[ "$(rc)" != 0 ] || fail "nopkg: succeeded"
cmp -s "$C/orig" "$C/sha256.sum" || fail "nopkg: sum changed"

# 6. prerelease names with `~`.
new_case tilde; mkpkgs 0.2.0~rc.1; run
[ "$(rc)" = 0 ] || fail "tilde: exit $(rc): $(cat "$C/out")"
grep -qF ' *dnsy_0.2.0~rc.1_amd64.deb' "$C/sha256.sum" || fail "tilde: deb line missing"
grep -qF ' *dnsy-0.2.0_rc.1-1.x86_64.rpm' "$C/sha256.sum" || fail "tilde: rpm line missing"
cp "$C"/pkg/* "$C"/; (cd "$C" && sha256sum -c sha256.sum > /dev/null 2>&1) || fail "tilde: sha256sum -c failed"
run; [ "$(wc -l < "$C/sha256.sum")" = 6 ] || fail "tilde: rerun duplicated"

if [ "$failures" -ne 0 ]; then echo "$failures failure(s)" >&2; exit 1; fi
echo "ok: update-sha256sum tests passed"

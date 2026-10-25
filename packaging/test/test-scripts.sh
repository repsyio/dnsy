#!/bin/sh
# Unit tests for the maintainer scripts: runs each one under `sh` (dash in CI) with stub commands
# on PATH and its absolute paths redirected into a scratch directory, then checks which commands
# it ran. Covers: no systemd (containers), systemd present, deb and rpm arguments, upgrade vs removal.
set -u
here=$(cd "$(dirname "$0")/.." && pwd)/scripts
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
failures=0
SH=$(command -v sh)
fail() { echo "FAIL: $*" >&2; failures=$((failures + 1)); }

# new_case <name> <with_systemd:yes|no> <with_sysusers:yes|no> <with_user:yes|no>
new_case() {
    C=$T/$1
    rm -rf "$C"
    mkdir -p "$C/bin" "$C/etc/dnsy" "$C/var/lib/dnsy" "$C/run"
    : > "$C/etc/dnsy/dnsy.toml"
    : > "$C/var/lib/dnsy/dnsy.db"
    : > "$C/calls"
    [ "$2" = yes ] && mkdir -p "$C/run/systemd/system"
    for cmd in systemctl chgrp userdel groupdel; do
        printf '#!/bin/sh\necho "%s $*" >> "%s"\n' "$cmd" "$C/calls" > "$C/bin/$cmd"
        chmod +x "$C/bin/$cmd"
    done
    if [ "$3" = yes ]; then
        printf '#!/bin/sh\necho "systemd-sysusers $*" >> "%s"\n' "$C/calls" > "$C/bin/systemd-sysusers"
        chmod +x "$C/bin/systemd-sysusers"
    fi
    # Only the utilities the scripts need, so no real systemctl or systemd-sysusers is ever found.
    for cmd in rm cat; do ln -s "$(command -v $cmd)" "$C/bin/$cmd"; done
    # getent: reports the user and group only when the case has them.
    printf '#!/bin/sh\n[ "%s" = yes ] && exit 0\nexit 2\n' "$4" > "$C/bin/getent"
    chmod +x "$C/bin/getent"
}

# run <script> <args...>: runs a copy of the script with paths redirected into $C.
run() {
    s=$1; shift
    sed -e "s#/run/systemd/system#$C/run/systemd/system#g" \
        -e "s#/var/lib/dnsy#$C/var/lib/dnsy#g" \
        -e "s#/etc/dnsy#$C/etc/dnsy#g" "$here/$s" > "$C/script.sh"
    PATH="$C/bin" "$SH" "$C/script.sh" "$@" > "$C/out" 2>&1
    echo $? > "$C/rc"
}

assert_calls() { # <case-desc> <expected>
    got=$(cat "$C/calls")
    [ "$got" = "$2" ] || fail "$1: calls were:
$got
want:
$2"
}
assert_rc0() { [ "$(cat "$C/rc")" = 0 ] || fail "$1: exit code $(cat "$C/rc"): $(cat "$C/out")"; }
assert_out() { grep -q "$2" "$C/out" || fail "$1: output lacks '$2'"; }

nl='
'

# postinst: no systemd at all (container): nothing is called, the hint is still printed.
new_case pi-container no no no
run postinst.sh configure
assert_rc0 "postinst container"
assert_calls "postinst container" ""
assert_out "postinst container" "edit .*/etc/dnsy/dnsy.toml"
assert_out "postinst container" "systemctl enable --now dnsy"

# postinst: systemd running, sysusers present and the group exists: user, group fix, reload; never enable/start.
new_case pi-systemd yes yes yes
run postinst.sh 1
assert_rc0 "postinst systemd"
assert_calls "postinst systemd" "systemd-sysusers dnsy.conf${nl}chgrp dnsy $C/etc/dnsy $C/etc/dnsy/dnsy.toml${nl}systemctl daemon-reload"
grep -q 'enable\|start' "$C/calls" && fail "postinst must never enable or start the service"

# postinst: sysusers present but no systemd running (container with the binary only): user created, no reload.
new_case pi-sysusers-only no yes yes
run postinst.sh configure
assert_rc0 "postinst sysusers only"
assert_calls "postinst sysusers only" "systemd-sysusers dnsy.conf${nl}chgrp dnsy $C/etc/dnsy $C/etc/dnsy/dnsy.toml"

# postinst: a failing systemd-sysusers or daemon-reload must not fail the install.
new_case pi-failing yes yes no
printf '#!/bin/sh\nexit 1\n' > "$C/bin/systemd-sysusers"
printf '#!/bin/sh\nexit 1\n' > "$C/bin/systemctl"
run postinst.sh configure
assert_rc0 "postinst tolerates failures"

# prerm: stops and disables on removal (deb "remove", rpm 0) ...
for arg in remove 0; do
    new_case "prerm-$arg" yes no no
    run prerm.sh "$arg"
    assert_rc0 "prerm $arg"
    assert_calls "prerm $arg" "systemctl stop dnsy.service${nl}systemctl disable dnsy.service"
done
# ... but not on upgrade (deb "upgrade", rpm 1) or when systemd is absent.
for arg in upgrade failed-upgrade deconfigure 1 2; do
    new_case "prerm-$arg" yes no no
    run prerm.sh "$arg"
    assert_rc0 "prerm $arg"
    assert_calls "prerm $arg" ""
done
new_case prerm-container no no no
run prerm.sh remove
assert_rc0 "prerm container"
assert_calls "prerm container" ""

# postrm: remove and rpm 0 reload systemd but keep user, group and data.
for arg in remove 0; do
    new_case "postrm-$arg" yes no yes
    run postrm.sh "$arg"
    assert_rc0 "postrm $arg"
    assert_calls "postrm $arg" "systemctl daemon-reload"
    [ -f "$C/var/lib/dnsy/dnsy.db" ] || fail "postrm $arg deleted /var/lib/dnsy"
    [ -f "$C/etc/dnsy/dnsy.toml" ] || fail "postrm $arg deleted the config"
done
# upgrade (deb upgrade, rpm 1) and failed-upgrade touch nothing.
for arg in upgrade failed-upgrade abort-install 1; do
    new_case "postrm-$arg" yes no yes
    run postrm.sh "$arg"
    assert_rc0 "postrm $arg"
    assert_calls "postrm $arg" ""
    [ -f "$C/var/lib/dnsy/dnsy.db" ] || fail "postrm $arg deleted /var/lib/dnsy"
done
# purge removes the data directory, the user and the group.
new_case postrm-purge yes no yes
run postrm.sh purge
assert_rc0 "postrm purge"
assert_calls "postrm purge" "userdel dnsy${nl}groupdel dnsy${nl}systemctl daemon-reload"
[ ! -e "$C/var/lib/dnsy" ] || fail "purge left /var/lib/dnsy"
# purge with no user (never created) and no systemd still succeeds and removes the data.
new_case postrm-purge-bare no no no
run postrm.sh purge
assert_rc0 "postrm purge bare"
assert_calls "postrm purge bare" ""
[ ! -e "$C/var/lib/dnsy" ] || fail "bare purge left /var/lib/dnsy"

if [ "$failures" -ne 0 ]; then
    echo "$failures failure(s)" >&2
    exit 1
fi
echo "all maintainer script tests passed"

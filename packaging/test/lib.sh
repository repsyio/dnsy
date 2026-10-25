# shellcheck shell=sh
# Shared helpers for verify-deb.sh and verify-rpm.sh (POSIX sh, sourced). Runs inside a container.
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok: $*"; }
assert_file() { [ -f "$1" ] || fail "$1 is missing"; }
assert_absent() { [ ! -e "$1" ] || fail "$1 should not exist"; }
assert_mode() { [ "$(stat -c %a "$1")" = "$2" ] || fail "$1 mode is $(stat -c %a "$1"), want $2"; }
assert_user() { getent passwd dnsy >/dev/null || fail "user dnsy is missing"; }
assert_no_user() { ! getent passwd dnsy >/dev/null || fail "user dnsy still exists"; }

# Checks that must hold right after an install, whatever the format.
check_installed() {
    assert_file /usr/bin/dnsy
    assert_file /etc/dnsy/dnsy.toml
    assert_file /usr/lib/systemd/system/dnsy.service
    assert_file /usr/lib/sysusers.d/dnsy.conf
    assert_mode /etc/dnsy/dnsy.toml 640
    grep -q '^ExecStart=/usr/bin/dnsy ' /usr/lib/systemd/system/dnsy.service || fail "unit ExecStart is not /usr/bin/dnsy"
    out=$(dnsy version) || fail "dnsy version failed"
    case "$out" in *"$VERSION"*) ok "dnsy version: $out" ;; *) fail "dnsy version '$out' does not mention $VERSION" ;; esac
    # The package must neither enable nor start the service (port 53 clashes with systemd-resolved).
    assert_absent /etc/systemd/system/multi-user.target.wants/dnsy.service
    assert_absent /run/systemd/system
    ! pgrep -x dnsy >/dev/null 2>&1 || fail "dnsy is running after install"
    # A container has no systemd; the user exists only when systemd-sysusers is available.
    if command -v systemd-sysusers >/dev/null 2>&1; then
        assert_user
        ok "service user created by systemd-sysusers"
    else
        assert_no_user
        ok "no systemd-sysusers: the guard skipped user creation"
    fi
}

# Makes the user and data directory a real host would have, so removal paths can be checked.
fake_host_state() {
    getent group dnsy >/dev/null || groupadd --system dnsy
    getent passwd dnsy >/dev/null || useradd --system --gid dnsy --home-dir /var/lib/dnsy --shell /usr/sbin/nologin dnsy
    mkdir -p /var/lib/dnsy
    echo data > /var/lib/dnsy/dnsy.db
}

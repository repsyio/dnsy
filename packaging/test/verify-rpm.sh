#!/bin/sh
# Installs, reinstalls and removes the .rpm in /pkg inside a container (no systemd).
# Usage: VERSION=0.1.0 sh verify-rpm.sh   (the package directory is mounted at /pkg)
set -eu
# shellcheck source=packaging/test/lib.sh
. "$(dirname "$0")/lib.sh"
: "${VERSION:?}"

arch=$(uname -m)
rpmfile=$(ls /pkg/dnsy-*."$arch".rpm)
dnf install -y -q "$rpmfile" >/dev/null
check_installed

rpm -ql dnsy | grep -qx /usr/bin/dnsy || fail "rpm -ql does not list /usr/bin/dnsy"
rpm -ql dnsy | grep -qx /usr/lib/systemd/system/dnsy.service || fail "rpm -ql does not list the unit"
rpm -ql dnsy | grep -qx /usr/lib/sysusers.d/dnsy.conf || fail "rpm -ql does not list the sysusers file"
[ "$(rpm -q --qf '%{ARCH}' dnsy)" = "$arch" ] || fail "wrong architecture"
rpm -q --qf '[%{FILEFLAGS:fflags} %{FILENAMES}\n]' dnsy | grep -q '^cn.* /etc/dnsy/dnsy.toml$' || fail "dnsy.toml is not %config(noreplace)"
ok "files, config(noreplace) flag and rpm metadata"

# A reinstall keeps an edited config (noreplace).
echo '# edited by the admin' >> /etc/dnsy/dnsy.toml
dnf reinstall -y -q "$rpmfile" >/dev/null
grep -q 'edited by the admin' /etc/dnsy/dnsy.toml || fail "reinstall overwrote the edited config"
ok "reinstall keeps the edited config"

fake_host_state
dnf remove -y -q dnsy >/dev/null
assert_absent /usr/bin/dnsy
assert_absent /usr/lib/systemd/system/dnsy.service
# rpm keeps an edited config as .rpmsave; the user and data are never removed by rpm.
assert_file /etc/dnsy/dnsy.toml.rpmsave
assert_user
assert_file /var/lib/dnsy/dnsy.db
ok "remove keeps the edited config (.rpmsave), the user and /var/lib/dnsy"

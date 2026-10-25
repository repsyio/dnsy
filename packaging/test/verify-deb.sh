#!/bin/sh
# Installs, reinstalls, removes and purges the .deb in /pkg inside a container (no systemd).
# Usage: VERSION=0.1.0 sh verify-deb.sh   (the package directory is mounted at /pkg)
set -eu
# shellcheck source=packaging/test/lib.sh
. "$(dirname "$0")/lib.sh"
: "${VERSION:?}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
arch=$(dpkg --print-architecture)
deb=$(ls /pkg/dnsy_*_"$arch".deb)
apt-get install -y -qq "$deb" >/dev/null
check_installed

dpkg -L dnsy | grep -qx /usr/bin/dnsy || fail "dpkg -L does not list /usr/bin/dnsy"
dpkg -L dnsy | grep -qx /usr/lib/systemd/system/dnsy.service || fail "dpkg -L does not list the unit"
dpkg -L dnsy | grep -qx /usr/lib/sysusers.d/dnsy.conf || fail "dpkg -L does not list the sysusers file"
dpkg -s dnsy | grep -q '^Architecture: '"$arch" || fail "wrong architecture"
dpkg-query -W -f='${Conffiles}\n' dnsy | grep -q /etc/dnsy/dnsy.toml || fail "dnsy.toml is not a conffile"
ok "files, conffile and dpkg metadata"

# A reinstall keeps an edited config.
echo '# edited by the admin' >> /etc/dnsy/dnsy.toml
apt-get install -y -qq --reinstall -o Dpkg::Options::=--force-confold "$deb" >/dev/null
grep -q 'edited by the admin' /etc/dnsy/dnsy.toml || fail "reinstall overwrote the edited config"
ok "reinstall keeps the edited config"

fake_host_state
apt-get remove -y -qq dnsy >/dev/null
assert_absent /usr/bin/dnsy
assert_absent /usr/lib/systemd/system/dnsy.service
assert_file /etc/dnsy/dnsy.toml
assert_user
assert_file /var/lib/dnsy/dnsy.db
ok "remove keeps /etc/dnsy, the user and /var/lib/dnsy"

apt-get purge -y -qq dnsy >/dev/null
assert_absent /etc/dnsy/dnsy.toml
assert_absent /var/lib/dnsy
assert_no_user
! getent group dnsy >/dev/null || fail "group dnsy still exists after purge"
ok "purge removes the config, the data directory and the user"

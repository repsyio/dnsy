#!/bin/sh
# Runs after the files are unpacked (dpkg: "configure", rpm: $1 = 1 install or 2 upgrade).
# Creates the service user and tells the admin what to do next. It never enables or starts the
# service: on many hosts systemd-resolved already holds port 53.
set -e

# A container (or chroot) has no systemd; the user is then simply not created.
if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers dnsy.conf || true
fi

# systemd creates the user's group only through sysusers, so hand the config to it when it exists.
if getent group dnsy >/dev/null 2>&1; then
    chgrp dnsy /etc/dnsy /etc/dnsy/dnsy.toml 2>/dev/null || true
fi

if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

cat <<'MSG'

DNSY is installed but not running. Next steps:
  1. edit /etc/dnsy/dnsy.toml
  2. systemctl enable --now dnsy
If systemd-resolved already uses port 53, see the headless install page:
https://github.com/repsyio/dnsy/blob/main/docs/book/src/headless.md

MSG
exit 0

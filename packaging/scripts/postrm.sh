#!/bin/sh
# Runs after the files are removed. Only a Debian purge deletes the user and the data directory;
# rpm never passes "purge" and so never does. Removing the package keeps /etc/dnsy/dnsy.toml.
set -e

case "$1" in
    remove | 0)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi
        ;;
    purge)
        rm -rf /var/lib/dnsy
        if getent passwd dnsy >/dev/null 2>&1; then
            userdel dnsy >/dev/null 2>&1 || true
        fi
        if getent group dnsy >/dev/null 2>&1; then
            groupdel dnsy >/dev/null 2>&1 || true
        fi
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl daemon-reload || true
        fi
        ;;
esac
exit 0

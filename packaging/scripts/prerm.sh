#!/bin/sh
# Runs before the files are removed. dpkg passes "remove" (also "upgrade", "deconfigure" and
# "failed-upgrade"); rpm passes the number of copies that remain (0 = last copy is going away,
# 1 = an upgrade). Stop and disable the service only on a real removal.
set -e

case "$1" in
    remove | 0)
        if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
            systemctl stop dnsy.service || true
            systemctl disable dnsy.service || true
        fi
        ;;
esac
exit 0

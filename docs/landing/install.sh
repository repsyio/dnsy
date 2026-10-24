#!/bin/sh
# DNSY installer: dnsy.dev/install.sh. Runs the installer that ships with the latest GitHub release,
# which downloads the right archive for this machine, verifies its SHA-256 and installs `dnsy`.
#   curl -fsSL https://dnsy.dev/install.sh | sh
# Read it first if you like: https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.sh
set -eu
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.sh | sh

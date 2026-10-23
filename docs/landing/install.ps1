# DNSY installer for Windows: dnsy.dev/install.ps1. Runs the installer that ships with the latest
# GitHub release, which downloads the Windows archive, verifies its SHA-256 and installs `dnsy`.
#   irm https://dnsy.dev/install.ps1 | iex
# Read it first if you like: https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.ps1
$ErrorActionPreference = 'Stop'
irm https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.ps1 | iex

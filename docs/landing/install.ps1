# DNSY installer for Windows: dnsy.dev/install.ps1. Runs the installer that ships with the latest
# GitHub release, which downloads the Windows archive, verifies its SHA-256 and installs `dnsy`.
#   irm https://dnsy.dev/install.ps1 | iex
# It asks where to install (just for you, or a local folder) and whether to write a starter config.
# Skip the questions with environment variables set before the command:
#   $env:DNSY_INSTALL_MODE = 'user' | 'local'      user: %USERPROFILE%\.cargo\bin, added to your PATH
#   $env:DNSY_INIT_CONFIG  = 'yes' | 'no'          local: .\dnsy in the current folder, PATH untouched
# Without a console to ask, the defaults are user and no config.
# Read it first if you like: https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.ps1
$ErrorActionPreference = 'Stop'

$interactive = [Environment]::UserInteractive -and -not [Console]::IsInputRedirected
$mode = $env:DNSY_INSTALL_MODE
$init = $env:DNSY_INIT_CONFIG

if (-not $mode -and $interactive) {
  Write-Host 'Where should DNSY be installed?'
  Write-Host "  1) Just for me   $env:USERPROFILE\.cargo\bin, added to your PATH"
  Write-Host "  2) This folder   $((Get-Location).Path)\dnsy, nothing outside it is touched"
  while (-not $mode) {
    $answer = Read-Host 'Choose 1 or 2 [1]'
    switch ($answer) {
      { $_ -in '', '1', 'user' } { $mode = 'user' }
      { $_ -in '2', 'local' } { $mode = 'local' }
      default { Write-Host 'Please answer 1 or 2.' }
    }
  }
}
if (-not $mode) { $mode = 'user' }
if ($mode -notin 'user', 'local') {
  throw "DNSY_INSTALL_MODE must be user or local, not $mode"
}

if ($mode -eq 'local') {
  $dir = Join-Path (Get-Location).Path 'dnsy'
  New-Item -ItemType Directory -Force -Path $dir | Out-Null
  # Unmanaged: the binary goes straight into the folder and the PATH is not edited.
  $env:DNSY_UNMANAGED_INSTALL = $dir
} else {
  $cargoHome = if ($env:CARGO_HOME) { $env:CARGO_HOME } else { Join-Path $env:USERPROFILE '.cargo' }
  $dir = Join-Path $cargoHome 'bin'
}

irm https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.ps1 | iex

$dnsy = Join-Path $dir 'dnsy.exe'
if (-not (Test-Path $dnsy)) { throw "the installer finished but $dnsy is missing" }

if ($mode -eq 'local') {
  $config = Join-Path $dir 'dnsy.toml'
} else {
  $config = Join-Path $env:APPDATA 'dnsy\dnsy.toml'
}

if (-not $init -and $interactive) {
  $answer = Read-Host "Write a starter config to $config now? [y/N]"
  $init = if ($answer -match '^(y|yes)$') { 'yes' } else { 'no' }
}

$written = $false
if ($init -eq 'yes') {
  & $dnsy config init --help *> $null
  if ($LASTEXITCODE -ne 0) {
    Write-Host 'This release has no `dnsy config init` yet; see https://dnsy.dev/docs/ for a sample config.'
  } else {
    # Unprivileged: port 5353 on loopback, state in .\dnsy-data of the folder you start dnsy in.
    & $dnsy --config $config config init --dev
    $written = ($LASTEXITCODE -eq 0)
  }
}

Write-Host ''
Write-Host "dnsy is installed: $dnsy"
if ($written -and $mode -eq 'local') {
  Write-Host "Next: cd $dir; .\dnsy.exe --config dnsy.toml serve"
} elseif ($written) {
  Write-Host "Next: dnsy --config $config serve   (data goes to .\dnsy-data; open a new terminal first so PATH is refreshed)"
} else {
  Write-Host 'Next: dnsy config init --help   (writes a starter config; --dev runs without administrator rights)'
}

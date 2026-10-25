#!/bin/sh
# DNSY installer: dnsy.dev/install.sh. Runs the installer that ships with the latest GitHub release,
# which downloads the right archive for this machine, verifies its SHA-256 and installs `dnsy`.
#   curl -fsSL https://dnsy.dev/install.sh | sh
# It asks where to install (system-wide, your user only, or a local folder) and whether to write a
# starter config. Skip the questions with flags (pass them after `sh -s --`):
#   curl -fsSL https://dnsy.dev/install.sh | sh -s -- --user --no-config
#     --global     /usr/local/bin for every user (uses sudo when you are not root)
#     --user       ~/.local/bin for you only
#     --local      ./dnsy in the current directory, nothing outside it is touched
#     --config     write a starter config after installing      --no-config   do not
# or with DNSY_INSTALL_MODE=global|user|local and DNSY_INIT_CONFIG=yes|no. Without a terminal to ask,
# the defaults are --user and --no-config.
# Read it first if you like: https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.sh
set -eu

INSTALLER_URL="${DNSY_INSTALLER_URL:-https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.sh}"
MODE="${DNSY_INSTALL_MODE:-}"
INIT="${DNSY_INIT_CONFIG:-}"

say() { printf '%s\n' "$*" >&2; }
die() { say "dnsy install: $*"; exit 1; }

while [ $# -gt 0 ]; do
    case "$1" in
        --global|--user|--local) MODE="${1#--}" ;;
        --config) INIT=yes ;;
        --no-config) INIT=no ;;
        -h|--help) sed -n '2,15p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option $1 (try --global, --user, --local, --config, --no-config)" ;;
    esac
    shift
done

# `curl | sh` has the script on stdin, so questions go to the terminal directly.
INTERACTIVE=0
if (exec </dev/tty) 2>/dev/null; then INTERACTIVE=1; fi

ask() {
    printf '%s' "$1" >&2
    IFS= read -r REPLY </dev/tty || REPLY=
    [ -n "$REPLY" ] || REPLY="$2"
}

if [ -z "$MODE" ] && [ "$INTERACTIVE" = 1 ]; then
    say "Where should DNSY be installed?"
    say "  1) System-wide   /usr/local/bin, for every user (needs sudo)"
    say "  2) Just for me   $HOME/.local/bin"
    say "  3) This folder   $PWD/dnsy, nothing outside it is touched"
    while :; do
        ask "Choose 1, 2 or 3 [2]: " 2
        case "$REPLY" in
            1|global) MODE=global; break ;;
            2|user) MODE=user; break ;;
            3|local) MODE=local; break ;;
            *) say "Please answer 1, 2 or 3." ;;
        esac
    done
fi
MODE="${MODE:-user}"

case "$MODE" in
    global) DIR=/usr/local/bin ;;
    user) DIR="$HOME/.local/bin" ;;
    local) DIR="$PWD/dnsy" ;;
    *) die "DNSY_INSTALL_MODE must be global, user or local, not $MODE" ;;
esac

# Root commands: sudo only when needed and only for the global install.
SUDO=
if [ "$MODE" = global ] && [ "$(id -u)" != 0 ]; then
    command -v sudo >/dev/null 2>&1 || die "a system-wide install needs root and sudo is not installed; run as root or choose --user"
    SUDO=sudo
fi

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

# Pin the transport for the real download; a test installer may be a local file.
case "$INSTALLER_URL" in
    https://*) curl --proto '=https' --tlsv1.2 -LsSf "$INSTALLER_URL" -o "$TMP/installer.sh" ;;
    *) curl -LsSf "$INSTALLER_URL" -o "$TMP/installer.sh" ;;
esac

say "Installing dnsy into $DIR"
$SUDO mkdir -p "$DIR"
# Unmanaged: the binary goes straight into DIR and no shell profile is edited.
$SUDO env DNSY_UNMANAGED_INSTALL="$DIR" sh "$TMP/installer.sh"

DNSY="$DIR/dnsy"
[ -x "$DNSY" ] || die "the installer finished but $DNSY is missing"

case "$MODE" in
    user)
        case ":$PATH:" in
            *":$DIR:"*) ;;
            *) say "Note: $DIR is not on your PATH. Add it, for example:"
               say "  echo 'export PATH=\"$DIR:\$PATH\"' >> ~/.profile" ;;
        esac ;;
esac

# Starter config.
if [ -z "$INIT" ] && [ "$INTERACTIVE" = 1 ]; then
    case "$MODE" in
        global) WHAT="/etc/dnsy/dnsy.toml" ;;
        user) WHAT="$HOME/.config/dnsy/dnsy.toml" ;;
        local) WHAT="$DIR/dnsy.toml" ;;
    esac
    ask "Write a starter config to $WHAT now? [y/N]: " n
    case "$REPLY" in y|Y|yes|YES|Yes) INIT=yes ;; *) INIT=no ;; esac
fi

CONFIG=
if [ "${INIT:-no}" = yes ]; then
    if ! "$DNSY" config init --help >/dev/null 2>&1; then
        say "This release has no \`dnsy config init\` yet; see https://dnsy.dev/docs/ for a sample config."
    else
        case "$MODE" in
            global)
                # Annotated defaults: DNS on port 53, state in /var/lib/dnsy.
                if $SUDO "$DNSY" --config /etc/dnsy/dnsy.toml config init; then CONFIG=/etc/dnsy/dnsy.toml; fi ;;
            user)
                # Unprivileged: port 5353 on loopback, state in ./dnsy-data of the directory you start dnsy in.
                if "$DNSY" --config "$HOME/.config/dnsy/dnsy.toml" config init --dev; then CONFIG="$HOME/.config/dnsy/dnsy.toml"; fi ;;
            local)
                if "$DNSY" --config "$DIR/dnsy.toml" config init --dev; then CONFIG="$DIR/dnsy.toml"; fi ;;
        esac
    fi
fi

say ""
say "dnsy is installed: $DNSY"
case "$MODE" in
    local) RUN="cd $DIR && ./dnsy" ;;
    *) RUN="dnsy" ;;
esac
if [ -n "$CONFIG" ]; then
    case "$MODE" in
        global) say "Next: sudo dnsy serve   (the config is $CONFIG)" ;;
        user) say "Next: dnsy --config $CONFIG serve   (data goes to ./dnsy-data)" ;;
        local) say "Next: cd $DIR && ./dnsy --config dnsy.toml serve" ;;
    esac
else
    say "Next: $RUN config init --help   (writes a starter config; --dev runs without root)"
fi

# Releases

DNSY is released as prebuilt binaries for Linux, macOS and Windows, built by
[cargo-dist](https://opensource.axo.dev/cargo-dist/) (`dist`) in GitHub Actions when a `v*` tag is
pushed. Every binary has the web UI compiled in. There is no container image and no Homebrew tap
in v1.

## What a release contains

| Target | Archive | Runner |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `dnsy-x86_64-unknown-linux-gnu.tar.xz` | ubuntu-22.04, `manylinux_2_28` container |
| `x86_64-unknown-linux-musl` | `dnsy-x86_64-unknown-linux-musl.tar.xz` | ubuntu-22.04 |
| `aarch64-unknown-linux-gnu` | `dnsy-aarch64-unknown-linux-gnu.tar.xz` | ubuntu-24.04-arm, `manylinux_2_28` container |
| `aarch64-unknown-linux-musl` | `dnsy-aarch64-unknown-linux-musl.tar.xz` | ubuntu-24.04-arm |
| `x86_64-apple-darwin` | `dnsy-x86_64-apple-darwin.tar.xz` | macos-15-intel |
| `aarch64-apple-darwin` | `dnsy-aarch64-apple-darwin.tar.xz` | macos-14 |
| `x86_64-pc-windows-msvc` | `dnsy-x86_64-pc-windows-msvc.zip` | windows-2022 |

Native installers sit beside the archives:

| Target | Installer | Runner |
| --- | --- | --- |
| `x86_64-apple-darwin` | `dnsy-x86_64-apple-darwin.pkg` | macos-15-intel |
| `aarch64-apple-darwin` | `dnsy-aarch64-apple-darwin.pkg` | macos-14 |
| `x86_64-pc-windows-msvc` | `dnsy-x86_64-pc-windows-msvc.msi` | windows-2022 |

Linux distribution packages are built from the two `gnu` archives after the release exists:

| Package | File | Built by |
| --- | --- | --- |
| Debian and Ubuntu, x86_64 | `dnsy_<ver>_amd64.deb` | `package-linux.yml` on ubuntu-24.04 |
| Debian and Ubuntu, arm64 | `dnsy_<ver>_arm64.deb` | `package-linux.yml` on ubuntu-24.04 |
| RHEL, Rocky, Alma, Fedora, x86_64 | `dnsy-<ver>-1.x86_64.rpm` | `package-linux.yml` on ubuntu-24.04 |
| RHEL, Rocky, Alma, Fedora, arm64 | `dnsy-<ver>-1.aarch64.rpm` | `package-linux.yml` on ubuntu-24.04 |

Each archive holds `dnsy` (`dnsy.exe` on Windows), `LICENSE`, `README.md`, `CHANGELOG.md` and the sample config `dnsy.toml`.
Next to the archives the release has `dnsy-installer.sh` (Linux and macOS), `dnsy-installer.ps1`
(Windows), the two `.pkg` files and the `.msi` above, the four Linux packages (each with its own
`.sha256`), `source.tar.gz`, one `<file>.sha256` per archive and package, and a combined `sha256.sum`.

`sha256.sum` covers the seven archives, `source.tar.gz` and the four Linux packages. dist writes it
before the packages exist, so `package-linux.yml` adds their lines afterwards
(`scripts/update-sha256sum.sh`: same `<sha256> *<file>` format, sorted by name, an existing line for
the same file is replaced, so a re-run never duplicates) and re-uploads it. The two script installers,
the `.pkg` files and the `.msi` are **not** in `sha256.sum` and have no `.sha256` file: dist
checksums archives only, as the installers of v0.1.0 show, and it treats `.pkg` and `.msi` as
installers too (not confirmed against a release that has them). For those, rely on the
HTTPS download from the release page. To verify a download, put it next to `sha256.sum` and run
`sha256sum -c sha256.sum --ignore-missing` (macOS: `shasum -a 256 -c sha256.sum --ignore-missing`). The macOS and Windows packages hold only the binary (no `LICENSE`, `README.md` or sample
config; use `dnsy config init` to write a config).

The `gnu` builds (x86_64 and aarch64) are built inside `quay.io/pypa/manylinux_2_28_<arch>`
containers and need glibc 2.28 or newer: RHEL, Rocky and Alma 8+, Debian 10+, Ubuntu 20.04+. Use
the `musl` builds on older or glibc-free distributions such as Alpine. The `glibc-floor` job in
`release-verify.yml` builds the same binary in the same images and runs
`scripts/check-glibc-floor.sh`, which fails the release if `objdump -T` shows any `GLIBC_` symbol
version above 2.28. Binaries and packages are not code-signed or notarised
(see [Unsigned packages](#unsigned-packages)).

## Installing a release

```sh
# Linux and macOS: asks where to install and whether to write a starter config
curl -fsSL https://dnsy.dev/install.sh | sh
```

```powershell
# Windows
irm https://dnsy.dev/install.ps1 | iex
```

`dnsy.dev/install.sh` and `dnsy.dev/install.ps1` are small wrappers (sources in `docs/landing/`)
that run the installer attached to the latest release, so they never go stale. They ask two questions
on a terminal (they read the answers from `/dev/tty`, so `curl | sh` works):

1. **Where to install.** `install.sh` offers system-wide (`/usr/local/bin`, uses `sudo` unless you are
   root), just you (`~/.local/bin`) or a local folder (`./dnsy`, nothing outside it is touched). On
   Windows the choices are just you (`%USERPROFILE%\.cargo\bin`, added to your PATH) or a local
   folder. The binary goes only into that folder and no shell profile is edited; if it is not on your PATH the script prints the line to add.
2. **A starter config.** If you say yes it runs `dnsy config init`: the annotated system config at
   `/etc/dnsy/dnsy.toml` for a system-wide install, and a `--dev` config (port 5353 on loopback, no
   root needed) at `~/.config/dnsy/dnsy.toml` or next to a local install. A release older than the
   one that added `config init` skips this step.

To skip the questions, pass flags after `sh -s --` or set environment variables:

```sh
curl -fsSL https://dnsy.dev/install.sh | sh -s -- --user --no-config
# --global | --user | --local     DNSY_INSTALL_MODE=global|user|local
# --config | --no-config          DNSY_INIT_CONFIG=yes|no
```

```powershell
$env:DNSY_INSTALL_MODE = 'local'; $env:DNSY_INIT_CONFIG = 'no'; irm https://dnsy.dev/install.ps1 | iex
```

Without a terminal to ask, the defaults are a user install and no config. The direct commands work
too, and are what the wrappers run (they install to `$CARGO_HOME/bin`):

```sh
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.sh | sh
```

```powershell
powershell -ExecutionPolicy Bypass -c "irm https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.ps1 | iex"
```

### macOS package

There is one `.pkg` per architecture (`aarch64` for Apple silicon, `x86_64` for Intel). Download it
from the release page and install it for all users:

```sh
sudo installer -pkg dnsy-aarch64-apple-darwin.pkg -target /
dnsy version
```

The package identifier is `dev.dnsy.dnsy` and it installs `dnsy` under `/usr/local/bin`
(`pkgutil --files dev.dnsy.dnsy` lists what it installed). macOS has no uninstaller for `.pkg`
files: delete `/usr/local/bin/dnsy` and run `sudo pkgutil --forget dev.dnsy.dnsy`.

### Windows package

```powershell
msiexec /i dnsy-x86_64-pc-windows-msvc.msi /qn
```

The MSI is per machine (run it from an elevated prompt). It installs `dnsy.exe` to
`C:\Program Files\dnsy\bin` and adds that folder to the system `PATH`; open a new terminal before
running `dnsy`. Upgrades replace the previous version in place (the upgrade code is fixed in
`crates/dnsy/Cargo.toml` and must never change). Remove it with `msiexec /x
dnsy-x86_64-pc-windows-msvc.msi /qn` or from Apps in Settings. Without `/qn` the installer shows a
wizard where the PATH entry can be deselected.

### Linux packages (.deb and .rpm)

Download the file for your architecture from the release page (the version in the name has no
leading `v`; a pre-release such as `0.2.0-rc.1` is `0.2.0~rc.1` in the file name, so that it sorts
before `0.2.0`) and install it with the package manager, which resolves nothing extra (the binary
has no runtime dependencies):

```sh
sudo apt install ./dnsy_0.1.0_amd64.deb          # Debian, Ubuntu (arm64: _arm64.deb)
sudo dnf install ./dnsy-0.1.0-1.x86_64.rpm       # RHEL, Rocky, Alma, Fedora (arm64: .aarch64.rpm)
dnsy version
```

They need glibc 2.28 or newer, like the `gnu` archives (see above). Each package installs:

| Path | What |
| --- | --- |
| `/usr/bin/dnsy` | the binary (the same one as in the `gnu` archive) |
| `/etc/dnsy/dnsy.toml` | the annotated sample config, mode 0640; a `conffile` (deb) or `%config(noreplace)` (rpm), so your edits survive upgrades |
| `/usr/lib/systemd/system/dnsy.service` | the hardened [unit](headless.md) |
| `/usr/lib/sysusers.d/dnsy.conf` | creates the `dnsy` user and group |

The install script creates the `dnsy` user with `systemd-sysusers` and reloads systemd, then prints
what to do next. **It never enables or starts the service**: on many hosts `systemd-resolved`
already holds port 53, so edit `/etc/dnsy/dnsy.toml`, free the port if needed, and run
`sudo systemctl enable --now dnsy`. See [Headless and service install](headless.md). Without systemd
(a container) the user is not created and nothing else is attempted.

- **Upgrade** (`apt install ./newer.deb`, `dnf install ./newer.rpm`): replaces the binary and unit;
  keeps and does not restart a running service until you restart it; keeps `dnsy.toml` (dpkg asks
  if you and the package both changed it, rpm writes `dnsy.toml.rpmnew`).
- **Remove** (`sudo apt remove dnsy`, `sudo dnf remove dnsy`): stops and disables the service and
  deletes the binary and unit. `/etc/dnsy`, the `dnsy` user and `/var/lib/dnsy` stay (rpm saves an
  edited config as `dnsy.toml.rpmsave`).
- **Purge** (`sudo apt purge dnsy`, Debian only): additionally deletes the config, the `dnsy` user
  and group, and `/var/lib/dnsy`, including the database and DNSSEC keys. rpm has no purge and never
  deletes the user or `/var/lib/dnsy`.

What the packages do not do: they are not signed and there is no apt or yum repository yet, so
`apt upgrade` will not find new versions (download the new file); they do not enable, start or
restart the service; they do not touch `systemd-resolved`, the firewall or DNS settings; and they
install no man page, shell completions or `LICENSE` file. The Debian maintainer field is the
placeholder `DNSY maintainers <firat@repsy.io>`.

### Unsigned packages

The `.pkg` and `.msi` files are not signed (no Apple Developer ID, no Windows code-signing
certificate), so both operating systems warn (the `.deb` and `.rpm` files are unsigned too, and
`dnf` prints a warning about that for a local file):

- **macOS 15 (Sequoia) and later**: Gatekeeper blocks a quarantined unsigned `.pkg` opened from the
  Finder or installed from a browser download. Open **System Settings > Privacy & Security**, scroll
  to the message about `dnsy-...pkg` and choose **Open Anyway**. Running `sudo installer` in a
  terminal on a file fetched with `curl` (which sets no quarantine flag) is not blocked; for a
  browser download you can instead run `xattr -d com.apple.quarantine <file>.pkg`.
- **Windows**: SmartScreen shows "Windows protected your PC" for the `.msi`; choose **More info**
  then **Run anyway**. `msiexec /qn` does not show the prompt.

Verify the download against `sha256.sum` (below) before overriding either warning.

Or download an archive by hand and verify it:

```sh
v=v0.1.0
t=x86_64-unknown-linux-gnu
curl -LO https://github.com/repsyio/dnsy/releases/download/$v/dnsy-$t.tar.xz
curl -LO https://github.com/repsyio/dnsy/releases/download/$v/dnsy-$t.tar.xz.sha256
sha256sum -c dnsy-$t.tar.xz.sha256        # macOS: shasum -a 256 -c ...
tar xf dnsy-$t.tar.xz
dnsy-$t/dnsy version
```

Checksums protect against corrupted downloads; they are published beside the archives, so they are
not a signature. Inspect `dnsy-installer.sh` before piping it to a shell if that matters to you.

## How the pipeline works

Configuration lives in `dist-workspace.toml`; the workflow is `.github/workflows/release.yml`.

1. `plan` runs `dist host --steps=create` and computes the build matrix from the tag. It fails if
   the tag does not match the version in `Cargo.toml`.
2. `custom-release-verify` (`release-verify.yml`) builds the web UI and runs the embedded-UI test
   `ui_serves_brotli_when_accepted` with `--features embed-ui` in release mode; its `glibc-floor` job builds `dnsy` in the two
   manylinux_2_28 images and checks the glibc floor. No artifact is built when either fails.
3. `build-local-artifacts` runs once per target. Its prerequisite steps (`.github/build-setup.yml`)
   install pnpm and Node 24, run `pnpm install --frozen-lockfile && pnpm build` in `web/` (producing
   `web/dist/dnsy/browser`) and, outside the manylinux containers (no `apt-get` there), install
   `musl-tools`; then `dist build` compiles
   `dnsy --features embed-ui` with the `dist` profile, which inherits `[profile.release]` unchanged
   (fat LTO, one codegen unit, stripped, overflow checks, `panic = "unwind"`).
   On the macOS and Windows runners the same `dist build` also produces the `.pkg` (`pkgbuild` and
   `productbuild`, identifier from `[dist.mac-pkg-config]`) and the `.msi` (WiX 3 via cargo-wix, from
   `crates/dnsy/wix/main.wxs`; the WiX upgrade and PATH GUIDs are in `[package.metadata.wix]`).
4. `build-global-artifacts` creates the installers, `source.tar.gz` and `sha256.sum`.
5. `host` uploads everything and creates the GitHub Release (it has `contents: write`).
   Tags with a suffix such as `v0.2.0-rc.1` are marked as pre-releases.
6. `custom-package-linux` (`package-linux.yml`, a dist `publish-jobs` entry, the only other job with
   `contents: write`) runs after `host` and only for a stable tag (dist skips publish jobs for
   pre-releases). It downloads `dnsy-x86_64-unknown-linux-gnu.tar.xz` and the aarch64 one from the
   release, checks them against their `.sha256`, runs `scripts/package-linux.sh` (nfpm 2.48.0,
   downloaded by `scripts/install-nfpm.sh` and verified against the sha256 pinned in that script;
   configuration in `packaging/nfpm.yaml`, maintainer scripts in `packaging/scripts/`) and uploads
   the four packages and their `.sha256` files with `gh release upload --clobber`, then downloads
   the release's `sha256.sum`, adds the package lines with `scripts/update-sha256sum.sh`, checks every
   line of the result with `sha256sum -c` against the release's files, and uploads it back with
   `--clobber`. It fails if the release has no `sha256.sum` (it never creates one that lists only
   the packages). Nothing is compiled again. If it fails the release still exists; fix the cause and run **Package Linux**
   from the Actions tab (`workflow_dispatch`) with the tag, which rebuilds and replaces the
   packages using the packaging files of the branch you run it on, without moving the tag.

The `host` and `announce` jobs explicitly require `custom-release-verify` to have succeeded (dist's
default `always()` condition would otherwise accept skipped build jobs and publish after a failed
verify); the generator script re-applies this.

All actions are pinned by commit SHA. dist emits floating tags and write permissions, so
`scripts/generate-release-workflow.sh` runs `dist generate` and then re-applies the pins and the
`contents: read` default (and `contents: write` for `host` and `custom-package-linux`). Never edit `release.yml` by hand; change `dist-workspace.toml` or the
script and regenerate (needs `dist` 0.33.1 on `PATH`). `allow-dirty = ["ci"]` makes dist accept
the hardened file.

## Cutting v0.1.0 (maintainer steps)

One-time repository setup: Actions enabled, workflow permissions allow the `GITHUB_TOKEN` to create
releases (the `host` job requests `contents: write` itself), and the repository is public (the
free `ubuntu-24.04-arm` runners need that) or has larger arm runners.

1. On `main` with a green CI, move the `[Unreleased]` section of `CHANGELOG.md` under
   `## [0.1.0] - <date>` and keep an empty `[Unreleased]` above it. The release body uses this file
   plus dist's artifact table. Commit through a PR.
2. Check that `version` in the root `Cargo.toml` (`[workspace.package]`) is `0.1.0`. Bumping it is a
   normal PR that also updates `Cargo.lock`.
3. Run the `release-pre-check` workflow on `main` (Actions, release-pre-check, Run workflow) and wait
   for it to be green. It builds and tests on macOS and Windows and builds and installs the `.pkg`
   and `.msi`; none of that runs on pull requests, so this is where a platform break
   shows up before a tag. It also runs weekly on `main`. The release workflow does not wait for it, so a
   hotfix tag is never blocked by it.
4. Optional dry run on your machine (no tag, nothing published): with `dist` 0.33.1 installed run
   `dist plan` and `dist generate --check`. Add `dist build --artifacts=local --target=<triple>`
   after `cd web && pnpm install --frozen-lockfile && pnpm build` to build one archive.
5. Tag the merged commit and push the tag:

   ```sh
   git checkout main && git pull --ff-only
   git tag -a v0.1.0 -m "DNSY v0.1.0"
   git push origin v0.1.0
   ```

6. Watch the `Release` workflow. When it is green the release `v0.1.0` has the 7 archives, 2
   script installers, 2 `.pkg` files, the `.msi`, the 2 `.deb` and 2 `.rpm` packages, `source.tar.gz`, per-file `.sha256` files and `sha256.sum`.
7. Verify the packages by hand (`release-pre-check` does the same on a runner, but a release is the
   real test):
   - macOS (a Mac with no `dnsy` installed): download `dnsy-<arch>.pkg` in a browser, expect the
     Gatekeeper block, **Open Anyway**, finish the installer, then `dnsy version` prints `0.1.0` and
     `which dnsy` is `/usr/local/bin/dnsy`. Repeat the other architecture if you have the hardware.
   - Windows: download the `.msi`, expect the SmartScreen warning, install it (wizard and `/qn`),
     open a new terminal and run `dnsy version`; check `C:\Program Files\dnsy\bin\dnsy.exe` and the
     system `PATH`; install it again over itself and over an older build (no second Apps entry);
     uninstall and check both are gone.
8. Verify the Linux packages: `apt install ./dnsy_0.1.0_amd64.deb` on a clean Ubuntu or Debian host
   and `dnf install ./dnsy-0.1.0-1.x86_64.rpm` on a clean Rocky or Fedora host; `dnsy version`
   prints `0.1.0`, `systemctl status dnsy` shows the unit loaded but inactive and disabled, and
   `apt purge dnsy` / `dnf remove dnsy` behave as described above. The `packages` workflow runs
   these steps in containers on pull requests, but only a tag exercises the download from the
   release and the upload.
9. Verify: download `sha256.sum` and the archives and run `sha256sum -c sha256.sum --ignore-missing`;
   run the installer on a clean Linux and a clean Windows machine; `dnsy version` must print
   `0.1.0` and `/` on the web port must serve the UI (embedded).

If a build fails, fix forward and move to a new tag (`v0.1.1`); a half-created release can be
deleted in the GitHub UI, after which the tag may be deleted and re-pushed only if no one has
consumed it.

# Releases

DNSY is released as prebuilt binaries for Linux, macOS and Windows, built by
[cargo-dist](https://opensource.axo.dev/cargo-dist/) (`dist`) in GitHub Actions when a `v*` tag is
pushed. Every binary has the web UI compiled in. There is no container image and no Homebrew tap
in v1.

## What a release contains

| Target | Archive | Runner |
| --- | --- | --- |
| `x86_64-unknown-linux-gnu` | `dnsy-x86_64-unknown-linux-gnu.tar.xz` | ubuntu-22.04 |
| `x86_64-unknown-linux-musl` | `dnsy-x86_64-unknown-linux-musl.tar.xz` | ubuntu-22.04 |
| `aarch64-unknown-linux-gnu` | `dnsy-aarch64-unknown-linux-gnu.tar.xz` | ubuntu-24.04-arm |
| `aarch64-unknown-linux-musl` | `dnsy-aarch64-unknown-linux-musl.tar.xz` | ubuntu-24.04-arm |
| `x86_64-apple-darwin` | `dnsy-x86_64-apple-darwin.tar.xz` | macos-15-intel |
| `aarch64-apple-darwin` | `dnsy-aarch64-apple-darwin.tar.xz` | macos-14 |
| `x86_64-pc-windows-msvc` | `dnsy-x86_64-pc-windows-msvc.zip` | windows-2022 |

Each archive holds `dnsy` (`dnsy.exe` on Windows), `LICENSE`, `README.md` and `CHANGELOG.md`.
Next to the archives the release has `dnsy-installer.sh` (Linux and macOS), `dnsy-installer.ps1`
(Windows), `source.tar.gz`, one `<file>.sha256` per file and a combined `sha256.sum`.

The `gnu` builds link glibc 2.35 or newer (ubuntu-22.04); use the `musl` builds on older or
glibc-free distributions such as Alpine. Binaries are not code-signed or notarised: macOS
Gatekeeper and Windows SmartScreen may warn on first run.

## Installing a release

```sh
# Linux and macOS: installs to $CARGO_HOME/bin (default ~/.cargo/bin)
curl --proto '=https' --tlsv1.2 -LsSf \
  https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.sh | sh
```

```powershell
# Windows
powershell -ExecutionPolicy Bypass -c "irm https://github.com/repsyio/dnsy/releases/latest/download/dnsy-installer.ps1 | iex"
```

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
   `ui_serves_brotli_when_accepted` with `--features embed-ui` in release mode. No artifact is built
   when it fails.
3. `build-local-artifacts` runs once per target. Its prerequisite steps (`.github/workflows/build-setup.yml`)
   install pnpm and Node 24, run `pnpm install --frozen-lockfile && pnpm build` in `web/` (producing
   `web/dist/dnsy/browser`) and install `musl-tools`; then `dist build` compiles
   `dnsy --features embed-ui` with the `dist` profile, which inherits `[profile.release]` unchanged
   (fat LTO, one codegen unit, stripped, overflow checks, `panic = "unwind"`).
4. `build-global-artifacts` creates the installers, `source.tar.gz` and `sha256.sum`.
5. `host` uploads everything and creates the GitHub Release (the only job with `contents: write`).
   Tags with a suffix such as `v0.2.0-rc.1` are marked as pre-releases.

The `host` and `announce` jobs explicitly require `custom-release-verify` to have succeeded (dist's
default `always()` condition would otherwise accept skipped build jobs and publish after a failed
verify); the generator script re-applies this.

All actions are pinned by commit SHA. dist emits floating tags and write permissions, so
`scripts/generate-release-workflow.sh` runs `dist generate` and then re-applies the pins and the
`contents: read` default. Never edit `release.yml` by hand; change `dist-workspace.toml` or the
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
3. Optional dry run on your machine (no tag, nothing published): with `dist` 0.33.1 installed run
   `dist plan` and `dist generate --check`. Add `dist build --artifacts=local --target=<triple>`
   after `cd web && pnpm install --frozen-lockfile && pnpm build` to build one archive.
4. Tag the merged commit and push the tag:

   ```sh
   git checkout main && git pull --ff-only
   git tag -a v0.1.0 -m "DNSY v0.1.0"
   git push origin v0.1.0
   ```

5. Watch the `Release` workflow. When it is green the release `v0.1.0` has the 7 archives, 2
   installers, `source.tar.gz`, per-file `.sha256` files and `sha256.sum`.
6. Verify: download `sha256.sum` and the archives and run `sha256sum -c sha256.sum --ignore-missing`;
   run the installer on a clean Linux and a clean Windows machine; `dnsy version` must print
   `0.1.0` and `/` on the web port must serve the UI (embedded).

If a build fails, fix forward and move to a new tag (`v0.1.1`); a half-created release can be
deleted in the GitHub UI, after which the tag may be deleted and re-pushed only if no one has
consumed it.

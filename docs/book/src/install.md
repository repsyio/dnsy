# Install

DNSY is one binary, `dnsy`. It needs no runtime dependencies: SQLite is bundled and TLS uses
`rustls`.

## Prebuilt binaries

Every tagged release publishes archives and installers for Linux, macOS and Windows with the web
UI embedded; see [Releases](release.md) for the targets, installers and checksum verification.

Every archive also holds `dnsy.toml`, an annotated sample configuration. Copy it to
`/etc/dnsy/dnsy.toml` or let the binary write it for you, see [Starter configuration](#starter-configuration).

## From source

```sh
git clone https://github.com/repsyio/dnsy && cd dnsy
cargo build --release -p dnsy          # no node needed; the UI paths answer 404
```

To embed the web UI, build it first. `just build` does both steps (it needs node and pnpm):

```sh
just build                             # pnpm build in web/, then cargo build --features embed-ui
./target/release/dnsy version
```

The UI is compiled into the binary with the `embed-ui` feature from `web/dist/dnsy/browser`.
Building that feature without `web/dist` prints a warning and fails to compile, so run
`just build` rather than passing the feature by hand.

## Starter configuration

A fresh install has no config file, and the defaults assume root (port 53, `/etc/dnsy`,
`/var/lib/dnsy`). `dnsy config init` writes the annotated starter file to the `--config` path
(default `/etc/dnsy/dnsy.toml`, parent directories are created):

```sh
sudo dnsy config init                  # the annotated defaults, the same text as the archive's dnsy.toml
dnsy --config dnsy.toml config init --dev
dnsy --config dnsy.toml serve
```

`--dev` writes a configuration that runs without privileges: DNS on `127.0.0.1:5353`, the API on
`127.0.0.1:5380`, state under `./dnsy-data` (relative to the working directory) and the public
upstreams `1.1.1.1` and `9.9.9.9`, so queries resolve. Try it with `dig @127.0.0.1 -p 5353 example.com`.
An existing file is never overwritten unless you pass `--force`.

## Release profile

`cargo build --release` uses fat LTO, one codegen unit, stripped symbols and overflow checks
(integer overflow panics instead of wrapping). Panics unwind: a panic ends one connection task,
not the process. A release binary with the UI embedded is about 17 MB (29 MB before the profile),
and a clean release build takes roughly three minutes on a laptop-class machine.

The embedded UI ships a brotli and a gzip copy of every text asset (written by `pnpm build` in
`web/`); the server picks one from `Accept-Encoding` and sends `Vary: Accept-Encoding`.

## Files and users

| Path | Purpose |
| --- | --- |
| `/etc/dnsy/dnsy.toml` | configuration (override with `--config` or `DNSY_CONFIG`) |
| `<server.data_dir>/dnsy.db` | SQLite database: users, tokens, rules, keys, query log |
| `<zones.dir>/*.json` | zone files |

Binding port 53 or 853 needs privilege: run as a dedicated non-root user and grant
`CAP_NET_BIND_SERVICE` (or listen on high ports behind a forwarder). The data directory, the
key passphrase file and TLS private keys should be readable by that user only.

## Build time

Every binary embeds its build timestamp (`dnsy version` prints it, `SOURCE_DATE_EPOCH` makes it
reproducible). DNSSEC validation uses it as a lower bound for a sane system clock.

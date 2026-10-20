# Install

DNSY is one binary, `dnsy`. It needs no runtime dependencies: SQLite is bundled and TLS uses
`rustls`.

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

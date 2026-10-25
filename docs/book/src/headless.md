# Headless and service install

This page covers running DNSY as a systemd service on a server with no desktop: a dedicated
service user, the hardened unit, freeing port 53, and reaching the web panel over SSH.

The unit and the user definition live in the repository as
[`examples/dnsy.service`](https://github.com/repsy/dnsy/blob/main/examples/dnsy.service) and
[`examples/dnsy.sysusers`](https://github.com/repsy/dnsy/blob/main/examples/dnsy.sysusers).
Distribution packages install them to `/usr/lib/systemd/system/dnsy.service` and
`/usr/lib/sysusers.d/dnsy.conf`. For a tarball or `cargo install` setup, copy them there yourself
(or to `/etc/systemd/system/dnsy.service` and `/etc/sysusers.d/dnsy.conf`).

## Service user

`dnsy.sysusers` is a [`sysusers.d`](https://www.freedesktop.org/software/systemd/man/sysusers.d.html)
file that creates a system user and group named `dnsy` with `/var/lib/dnsy` as its home:

```text
u dnsy - "DNSY DNS server" /var/lib/dnsy
```

```sh
sudo install -m 0644 examples/dnsy.sysusers /etc/sysusers.d/dnsy.conf
sudo systemd-sysusers
```

## Install and enable the unit

The unit runs `/usr/bin/dnsy --config /etc/dnsy/dnsy.toml serve`. `--config` is a global flag, and
`/etc/dnsy/dnsy.toml` is also its default. If the binary is elsewhere, for example
`/usr/local/bin/dnsy` from a tarball install, change that one `ExecStart=` line (or override it
with `sudo systemctl edit dnsy`).

```sh
sudo install -m 0644 examples/dnsy.service /etc/systemd/system/dnsy.service
sudo install -d -o root -g dnsy -m 0750 /etc/dnsy
sudo install -m 0640 -g dnsy examples/dnsy.toml /etc/dnsy/dnsy.toml
sudo systemctl daemon-reload
sudo systemctl enable --now dnsy
```

The unit sets `StateDirectory=dnsy` (so `/var/lib/dnsy`, the default `server.data_dir`, is created
and owned by the `dnsy` user) and `ConfigurationDirectory=dnsy` (`/etc/dnsy`). Keep `data_dir` and
`zones.dir` under `/var/lib/dnsy`: with `ProtectSystem=strict` that is the only writable path.

Hardening in the unit: the process runs as `dnsy`, never as root; `AmbientCapabilities` and
`CapabilityBoundingSet` hold only `CAP_NET_BIND_SERVICE`, which is what lets it bind port 53, 853
and 443; `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`,
`ProtectKernel*`, `RestrictAddressFamilies` (IPv4, IPv6 and Unix sockets only) and
`SystemCallFilter=@system-service` limit the rest. The unit restarts on failure.

Check it with `systemctl status dnsy`. After editing `dnsy.toml`, `sudo systemctl restart dnsy`.

## Port 53 and systemd-resolved

On Ubuntu and similar hosts `systemd-resolved` already holds `127.0.0.53:53`, and DNSY fails to
start with `address already in use`. Follow
[Port 53 and systemd-resolved](quickstart.md#port-53-and-systemd-resolved) to bind a different
address or turn the stub listener off, then `sudo systemctl restart dnsy`.

## The first-run bootstrap code

On a fresh data directory no users exist. Once every listener has bound, DNSY writes a one-time
bootstrap code (valid one hour, shown once) to standard error, which systemd sends to the journal:

```sh
journalctl -u dnsy | grep 'bootstrap code'
```

A start that fails to bind prints no code, so fix the bind error first (see
[Troubleshooting](troubleshooting.md)) and look again. Use the code in the web panel or API to
create the first administrator, as described in [Users, tokens and sessions](auth.md).

## Reaching the web panel and API

The API and web panel listen on loopback only (`api.listen = ["127.0.0.1:5380"]` by default), so
they are not reachable from other machines. From your workstation, forward the port over SSH:

```sh
ssh -L 5380:127.0.0.1:5380 user@dns-host
```

Then open `http://127.0.0.1:5380` locally. The REST API is served on the same port. Keep the API
on loopback unless you add TLS and a firewall rule; see [Security](security.md).

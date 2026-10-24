# Quickstart

1. Copy the sample configuration and adjust the paths and listen addresses:

   ```sh
   sudo install -d /etc/dnsy /var/lib/dnsy /var/lib/dnsy/zones
   sudo cp examples/dnsy.toml /etc/dnsy/dnsy.toml
   dnsy config check
   ```

   `config check` validates the file (unknown keys are errors), the zone files, and that the
   referenced certificate, key and passphrase files exist.

   Set `[resolver] upstreams` to the resolvers DNSY forwards to, for example
   `upstreams = ["1.1.1.1:53", "9.9.9.9:53"]`. With no upstreams DNSY logs a warning at startup,
   and every forwarded query answers SERVFAIL. Upstreams are seeded into the database on the first
   start only; after that, change them through the web UI or the API.

   To try without root, set `[dns] udp` and `tcp` to `127.0.0.1:5353` and `[server] data_dir` to a
   directory you own. The same overrides work from the environment, without editing the file:

   ```sh
   export DNSY_DNS__UDP='["127.0.0.1:5353"]' DNSY_DNS__TCP='["127.0.0.1:5353"]'
   export DNSY_SERVER__DATA_DIR="$HOME/dnsy-data"
   ```

2. Create the first user (a random password is printed once, or use `--password-stdin`):

   ```sh
   dnsy user create admin --role admin
   ```

   Starting the server with no users also prints a one-time bootstrap code for the first-run
   screen of the web UI.

3. Run it:

   ```sh
   dnsy serve
   ```

   The DNS listeners default to `0.0.0.0:53`, which needs root or `CAP_NET_BIND_SERVICE`; with
   the unprivileged override above they listen on `127.0.0.1:5353`. If the server exits with
   `address already in use` on port 53, see [Port 53 and systemd-resolved](#port-53-and-systemd-resolved).

   The API and UI listen on `[api] listen` (default `127.0.0.1:5380`). `GET /healthz` is
   liveness, `GET /readyz` checks that the database answers.

4. Query it:

   ```sh
   dig @127.0.0.1 -p 5353 example.com
   ```

   By default DNSY serves only loopback, private (RFC 1918, 100.64.0.0/10, ULA) and link-local
   clients, so a query from a public address is answered REFUSED. This keeps a fresh install from
   becoming an open resolver for the internet. To serve other networks add an ACL rule for them
   (`POST /acl`), or set `[limits] open_resolver = true` (with a non-zero `per_client_qps`, 50 by
   default) to answer everyone.

5. Add a zone by dropping a JSON file into `[zones] dir` (see [Zones](zones.md)); it is picked
   up without a restart. Export it with `dnsy zone export example.com`.

6. Create a token for scripts or DNS-over-HTTPS:

   ```sh
   dnsy token create --user admin --name laptop --scope dns:query --scope api:write
   ```

   The secret is printed once. `dns:query` tokens authenticate DoH clients; `api:*` tokens
   call the REST API.

## Port 53 and systemd-resolved

On Ubuntu and other systemd hosts, `systemd-resolved` answers on a stub listener at
`127.0.0.53:53`. Binding DNSY to `0.0.0.0:53` then fails with `address already in use`. Either:

- listen on an address the stub does not hold, for example your LAN address:

  ```toml
  [dns]
  udp = ["192.168.1.10:53"]
  tcp = ["192.168.1.10:53"]
  ```

- or turn the stub off and restart the resolver:

  ```sh
  sudo mkdir -p /etc/systemd/resolved.conf.d
  printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/dnsy.conf
  sudo systemctl restart systemd-resolved
  ```

  The host's `/etc/resolv.conf` still points at `127.0.0.53` afterwards, so point it at DNSY
  (for example `nameserver 127.0.0.1`) or name resolution on this host stops working.

Binding port 53 itself needs root or `CAP_NET_BIND_SERVICE`. Running on a high port, as in step 1,
avoids both.

## Command reference

| Command | What it does |
| --- | --- |
| `dnsy serve [--ready-file F]` | run the DNS listeners and the API; `--ready-file` writes the bound addresses as JSON (useful with port 0) |
| `dnsy config check` | validate the configuration |
| `dnsy migrate [--status]` | apply database migrations, or only report them |
| `dnsy user create\|reset-password\|disable\|enable\|list` | manage users (`--password-stdin`, else `DNSY_PASSWORD`, else generated); a disabled user cannot log in and their sessions and tokens stop working |
| `dnsy token create --user U --name N --scope S [--expires-days D]` | issue a token |
| `dnsy zone export <name> [--signed]` | print a zone as BIND text; `--signed` includes DNSSEC records |
| `dnsy dnssec keys list\|generate\|rollover\|ds <zone>` | inspect and manage signing keys, print DS records for the registrar |
| `dnsy dnssec ds-confirmed <zone>`, `dnsy dnssec rollover abort <zone>` | confirm the registrar published the new DS; abort a rollover that has not switched keys |
| `dnsy dnssec keys export\|import <file>`, `dnsy dnssec passphrase change` | encrypted key backup and restore; re-encrypt all keys under a new passphrase |
| `dnsy cache flush [<name>] [--subtree]` | flush a running server's cache through the API (`--token` or `DNSY_TOKEN`, `--url` to override) |
| `dnsy openapi` | print the OpenAPI document |
| `dnsy version` | print the version and build time |

All commands take `--config <file>` (default `/etc/dnsy/dnsy.toml`, or `DNSY_CONFIG`).
Administration commands open the database directly, so they work while the server runs.

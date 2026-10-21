# Quickstart

1. Copy the sample configuration and adjust the paths and listen addresses:

   ```sh
   sudo install -d /etc/dnsy /var/lib/dnsy /var/lib/dnsy/zones
   sudo cp examples/dnsy.toml /etc/dnsy/dnsy.toml
   dnsy config check
   ```

   `config check` validates the file (unknown keys are errors), the zone files, and that the
   referenced certificate, key and passphrase files exist. For a first try without root set
   `[dns] udp/tcp` to `127.0.0.1:5353` and `[server] data_dir` to a directory you own.

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

   The API and UI listen on `[api] listen` (default `127.0.0.1:5380`). `GET /healthz` is
   liveness, `GET /readyz` checks that the database answers.

4. Query it:

   ```sh
   dig @127.0.0.1 -p 5353 example.com
   ```

5. Add a zone by dropping a JSON file into `[zones] dir` (see [Zones](zones.md)); it is picked
   up without a restart. Export it with `dnsy zone export example.com`.

6. Create a token for scripts or DNS-over-HTTPS:

   ```sh
   dnsy token create --user admin --name laptop --scope dns:query --scope api:write
   ```

   The secret is printed once. `dns:query` tokens authenticate DoH clients; `api:*` tokens
   call the REST API.

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

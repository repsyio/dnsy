# Backup and restore

Everything DNSY persists is in two places.

| What | Where | Notes |
| --- | --- | --- |
| Database | `<server.data_dir>/dnsy.db` (plus `-wal` and `-shm`) | users, password hashes, tokens (hashed), sessions, ACL, rules, blocklist sources, upstream groups, client certificates, DNSSEC keys, query log and rollups |
| Zone files | `[zones] dir`, `*.json` | the source of truth for each zone, human readable |
| Configuration | `dnsy.toml`, TLS certificates and keys, `key_passphrase_file` | managed by you, not by DNSY |

The cache is memory only and needs no backup.

## Back up

Use SQLite's online backup so the copy is consistent while the server runs:

```sh
sqlite3 /var/lib/dnsy/dnsy.db ".backup '/backup/dnsy-$(date +%F).db'"
rsync -a /var/lib/dnsy/zones/ /backup/zones/
```

Copying `dnsy.db` together with its `-wal` file while the server is stopped works too. Zone files
can also be exported as BIND text (`dnsy zone export example.com`, `--signed` for the signed
form), which is useful as a portable copy but not a replacement for the JSON files.

The database holds DNSSEC private keys. Without a key passphrase (`dnssec.key_passphrase_file` or
`DNSY_DNSSEC_PASSPHRASE`) they are stored unencrypted, so protect backups like the keys
themselves, and keep the passphrase separately from the backup: a database copy is useless for
signing without it.

The database file is created with mode 0600 (its `-wal` and `-shm` files follow) and a missing
`data_dir` with 0700. Existing files and directories keep their modes, so check them after
restoring from a backup made by another user: `chmod 700 <data_dir>; chmod 600 <data_dir>/dnsy.db*`.

The query log can dominate the database size. Lower `[querylog] retention_days` to shrink the
backup; the rollups behind the dashboard are small: hourly and minute rows are kept for the last two
to three days only, older days are folded into `stats_day` (about 20 rows per day) and
`stats_top_day` (at most 15 000 rows per day). The fold is one-way, so a backup is the only way to
get the minute and hour detail of an old day back. The write-ahead log is truncated to 64 MiB
after a checkpoint (`journal_size_limit`), so a large purge does not leave a large `-wal` file.
The two query-log indexes add about 30 percent to the file size (see [Query log and
stats](query-log.md)).

## Restore

1. Stop `dnsy serve`.
2. Put `dnsy.db` back into `<data_dir>` (remove stale `dnsy.db-wal` and `dnsy.db-shm` files) and the
   zone files into `[zones] dir`.
3. Provide the same key passphrase as when the keys were created.
4. `dnsy config check`, then `dnsy migrate --status` to see that the database matches the binary.
5. Start the server. A database newer than the binary is refused; run the binary version that
   wrote it or a newer one.

After a restore of a signed zone check `dnsy dnssec keys list <zone>` and compare
`dnsy dnssec keys ds <zone>` with the DS at the registrar: they must match, otherwise validating
resolvers fail the zone.

## Moving to another host

Restore as above on the new host and point clients at it. DoT and DoH certificates are not part of
the backup: install them on the new host. Sessions survive a restore only until they expire;
tokens keep working because they are stored in the database.

# Upgrade and migrations

DNSY is one binary and one SQLite database. Upgrading means replacing the binary and letting it
migrate the database.

## Procedure

1. Read the [changelog](https://github.com/repsyio/dnsy/blob/main/CHANGELOG.md) for the new version.
2. [Back up](backup-restore.md) the database and the zone files.
3. Install the new binary (see [Install](install.md)).
4. `dnsy config check`: unknown keys are errors, so a removed or renamed key shows up here.
5. `dnsy migrate --status`: lists applied and pending migrations without changing anything.
6. Restart the service. `dnsy serve` applies pending migrations on start; `dnsy migrate` applies
   them without starting the server.
7. Check `GET /readyz` and `GET /api/v1/version`.

## Migration rules

- Migrations are numbered, applied in a set (merge order does not matter) and never edited after
  release; every change is a new migration.
- A database newer than the binary (a migration the binary does not know) is refused at start. To
  go back, restore the backup taken before the upgrade and run the older binary.
- There are no down-migrations. The backup is the rollback path.

## Rolling back

Stop the service, restore `dnsy.db` and the zone files from the backup, start the previous binary.
Zone files written by a newer version may use fields an older version rejects (unknown keys are
errors), which is another reason to restore the zones from the same backup.

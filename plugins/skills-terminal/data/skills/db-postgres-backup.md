Back up PostgreSQL or restore a dump while preserving the existing database.

## Inspect

Confirm source server version, database, extensions, size, destination space and recovery objective. Check `pg_dump --version` and `pg_restore --version`; choose a compatible client. Identify whether roles, tablespaces, external files or physical recovery are also required.

## Backup

Offer a user-run `pg_dump` for the named database with a protected output path. A dump writes files and can consume resources. Custom-format dumps support `pg_restore --list` inspection. They do not include every cluster-wide role or setting. Do not put passwords in command arguments or shell history.

## Restore and verify

Restore into an isolated new database first. Inspect the dump source before restoration: SQL, functions and ownership changes can execute privileged behavior. Do not add `--clean` or overwrite production by default. Verify required extensions, object counts, ownership and representative application queries. A file existing or a backup command exiting zero is not a verified restore. Keep the original database until the user has accepted the restored result.

Open a SQLite database or diagnose a missing file, wrong database, or read-only error.

## Inspect

Establish the exact file path and owning application. Use metadata to confirm it exists, is a regular file and has the expected size. Do not let a diagnostic open create an empty database at a mistyped path.

Use `sqlite3 -readonly <file>` with a single command, for example `PRAGMA database_list; PRAGMA user_version;`. Substitute the observed path and quote it. Read-only mode protects against ordinary SQL writes; do not load extensions or execute SQL copied from an unknown file.

## Interpret

SQLite is an embedded database file, not a server waiting on a port. The directory and related WAL/SHM files matter. A filesystem permission error differs from database locking. Do not bypass a live application's coordination by changing ownership or deleting journal files.

## Verify

Confirm the resolved file and expected schema using bounded `sqlite_schema` rows. For changes or a backup, identify the application's supported maintenance route and obtain the user's execution. Preserve all recovery files until a consistent backup is verified.

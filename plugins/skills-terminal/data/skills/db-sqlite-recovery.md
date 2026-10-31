SQLite is locked, WAL files are large, or a backup or integrity check is needed.

## Inspect

Identify the owning process, open file handles, database path and journal mode. Check whether a transaction is still active. A large WAL may be retained by readers; do not delete `-wal`, `-shm` or journal files to release a lock.

## Backup and diagnosis

Use SQLite's online backup facility or the application's supported export for a live database. A raw copy of only the main file may omit committed data in the WAL. Backup creation writes files and is the user's action. Protect the output and check disk space.

An integrity check can be expensive and exceed the assistant's 20-second limit. Offer it on a recovery copy or in a deliberate user-run maintenance step. Report exactly which check completed. Never describe `PRAGMA quick_check` as a complete application consistency audit.

## Recover and verify

Keep the original database and recovery files. Work on a separate copy; salvage can lose rows or constraints. Check recovered schema, meaningful row counts and application access before replacing the original. Checkpoint and vacuum operations are changes, not read-only diagnostics.

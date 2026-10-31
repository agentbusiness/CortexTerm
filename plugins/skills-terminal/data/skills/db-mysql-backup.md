Back up or restore MySQL or MariaDB and check that the result is usable.

## Inspect

Confirm source product/version, backup client version, storage engines, database, size and destination. Determine whether routines, triggers, events, users and external files are required. MySQL and MariaDB dump options and compatibility differ; inspect the installed client's help.

## Backup

Offer a protected user-run dump command for the chosen database. Explain consistency assumptions: `--single-transaction` is useful for transactional tables but does not make concurrent schema changes harmless or nontransactional tables consistent. Do not lock or stop production without an explicit maintenance plan. Keep credentials out of arguments.

## Restore and verify

Restore to an isolated database or server of a compatible release. Inspect an untrusted dump before executing it: it may contain account, routine or destructive statements. Verify objects, representative row counts, routines/events required by the application, and application reads/writes on the restored target. Keep original data until recovery is demonstrated. A compressed dump file passing a decompression check only proves that its archive can be read.

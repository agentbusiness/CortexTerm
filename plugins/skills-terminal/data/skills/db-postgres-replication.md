PostgreSQL replication lag, missing replicas, WAL growth, capacity, or durability questions.

## Inspect

Confirm primary/standby roles and server versions. `SELECT pg_is_in_recovery();` distinguishes recovery state. On the primary, inspect bounded rows from `pg_stat_replication`; inspect only relevant replication slots and their retained WAL positions. On a standby, compare receive/replay state and timestamps with current workload and clocks.

## Interpret

No recent replay timestamp during an idle workload is not proof of lag. Separate network receive lag, replay work, long transactions and disconnected consumers. WAL can be retained by slots or archiving; do not delete files from `pg_wal` to free space.

## Change and verify

Changing durability, dropping a slot, promoting a standby or rebuilding a replica are user-run operations with distinct recovery consequences. Identify consumers and backups first. Never present asynchronous replication as zero-data-loss failover. Recheck the same LSN progression, receiver state, retained bytes and application access after the agreed action. Establish the intended recovery point before any failover.

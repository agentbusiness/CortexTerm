Cassandra repair, snapshots, restore, node replacement, compaction or upgrade maintenance.

## Inspect

Record release, topology, replication, node health, disk space, repair history and the recovery objective. Determine whether this is routine maintenance or recovery from an identified fault. Read the exact release's operation help and documentation.

## Plan

A snapshot, incremental backup, repair and full backup are different things. A snapshot remaining on the failed node is not an independent recovery copy. Repair synchronizes replicas; it does not undo operator deletion or replace a backup. Incremental and full repair have different coverage and resource costs.

Repair, compaction, draining, decommissioning and replacing nodes are changes for the user to run. Do not call them read-only diagnostics or use them as generic fixes. Plan one node/range at a time according to the documented topology and available capacity. Never delete SSTables, commit logs or system keyspaces to free space.

## Verify

Check completion, node views, streaming/repair state and representative queries. Restore into an isolated compatible environment first. Keep original data and copies until the intended recovery is demonstrated; a snapshot command exiting zero is not a restore test.

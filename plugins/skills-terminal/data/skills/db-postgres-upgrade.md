Upgrade PostgreSQL, move a cluster, or recover from a major-version mismatch.

## Inspect

Distinguish a minor package update from a major data-format upgrade. Record server and client versions, extension versions, installation method, data directory, disk space, replicas and application compatibility. Do not point a new server binary at an old data directory and hope it starts.

## Plan

Choose one documented route for those versions: dump/restore, `pg_upgrade`, or a planned logical migration. Check the exact tool's prerequisites and compatibility check before scheduling the change. Include roles, extensions, authentication, jobs, replication and configuration. Keep a verified backup and a tested recovery target.

## Execute and verify

Present the ordered user-run procedure, expected downtime and decision points. Link-mode upgrades can limit rollback once the new cluster starts; explain that before choosing a mode. Do not delete the old cluster as part of installation. Afterward confirm the server identity, extensions, required maintenance/statistics work and representative application queries. A successful service start does not prove migration correctness.

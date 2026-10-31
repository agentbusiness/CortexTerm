Redis or Valkey persistence, replication, restart data loss, backup or recovery questions.

## Inspect

Confirm server/version, role, persistence mode and recovery goal. Inspect `INFO persistence` and `INFO replication`, selecting relevant fields. Inspect only named non-secret persistence settings when permitted. A container's filesystem and its persistent volume are different storage locations.

## Interpret

RDB snapshots, append-only logs and replication have different loss windows. A replica is not an independent backup against accidental deletion. A configured persistence setting does not prove the last save succeeded or storage survives container replacement.

## Change and recover

`SAVE`, `BGSAVE`, AOF rewriting, configuration changes, failover and restore write state or consume resources; the user runs them deliberately. Check free disk, memory/fork pressure, compatibility and documented file layout first. Do not delete AOF/RDB files or replace a live volume to clear an error.

## Verify

Recover into an isolated compatible instance. Check representative key types, TTLs, counts appropriate to the scope and application behavior. Recheck persistence status and logs after the agreed change. Keep the original persistence files until recovery is demonstrated.

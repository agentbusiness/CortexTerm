PostgreSQL blocked sessions, deadlocks, long transactions, or a query that appears stuck.

## Inspect

Use a bounded query of `pg_stat_activity`: PID, state, transaction age, wait-event type and wait event. Example: `SELECT pid, state, wait_event_type, wait_event FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid() LIMIT 20;`. Avoid full query text unless needed; it can contain private data. For the named PID, inspect `pg_blocking_pids(<pid>)`. Confirm the server and that the PID still belongs to the same session.

## Interpret

A lock wait is different from CPU work. Find the oldest blocking transaction and its application owner. An idle-in-transaction session can retain locks. Missing permissions mean the check is incomplete, not that there are no blockers. Deadlock logs show a cycle, not proof that a particular table needs an index.

## Change and verify

Explain whether a proposed cancellation stops one statement or terminates a whole connection. Both are user-run changes. Termination rolls back that session's transaction and may interrupt work. Prefer coordinating with the owner. After the chosen action, recheck the blocking chain and the original operation; a successful cancellation call alone does not establish recovery.

MySQL or MariaDB slow queries, connection exhaustion, blocking, or high server CPU.

## Inspect

Confirm product/version, exact query shape, relevant indexes and the failure interval. Inspect bounded session metadata without dumping query text or passwords. Separate connection-pool waits and locks from query execution.

Start with plain `EXPLAIN` for the exact query. Runtime analysis syntax differs by product and release and executes work; inspect documented support before proposing it. Query time-limit variables also differ: do not copy MySQL's settings into MariaDB unchanged.

## Interpret

Inspect access paths, estimated rows, filtering, joins and sorting. A full scan can be appropriate for a small table or a broad result. A returned preview limit does not guarantee a small scan. Identify the blocking transaction before suggesting that a session be killed.

## Change and verify

Offer one query, index, pool or transaction correction tied to evidence. Explain its write, memory and maintenance costs. The user runs changes and runtime measurements. Compare the same workload before/after; estimated costs do not prove a speedup.

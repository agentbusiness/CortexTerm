PostgreSQL slow queries, high database CPU, missing indexes, or query-plan questions.

## Inspect

Get the exact query with sensitive values replaced by parameters, relevant schema/indexes, server version and the time window. Check whether the application is waiting for a connection, a lock, disk, or query execution before suggesting an index.

Start with plain `EXPLAIN (FORMAT JSON)` under a short statement timeout. `EXPLAIN ANALYZE` executes the query; it needs a deliberate user-run measurement on an appropriate target. A SELECT can also call a function with side effects. Never analyze an unknown write as a read-only check.

## Interpret

Compare estimated row counts, access paths, join choices and sort operations. A sequential scan is not automatically wrong. Do not claim runtime speed from estimates or a toy dataset.

## Change and verify

Offer one evidence-backed query or index change, explaining storage and write costs. Measure the same workload before and after with comparable data and cache conditions. Record actual timing separately from the predicted plan improvement.

Decide whether a database command is inspection, execution, data change or maintenance.

## Inspect

Identify the actual engine, database, role and statement. Use a role restricted to the required reads. Confirm the endpoint before any proposal. Do not classify a command solely by its first word or filename.

## Distinguish effects

SELECT can call functions with effects. SQL `EXPLAIN ANALYZE` and Cypher `PROFILE` execute work. MongoDB `$out` and `$merge` write results. A stored procedure can change state. Database backup, restore, index creation, repair, vacuum and compaction are operational actions even when useful for diagnosis.

A LIMIT bounds returned rows, not necessarily scanned work. Use engine-supported timeouts and a bounded projection. Read-only transactions add protection where supported; they do not guarantee zero resource cost, cover every external side effect, or make arbitrary SQL safe.

## Respond

Let the risk engine decide what runs. If refused, explain the exact limitation and offer the scoped user-run command when needed. Separate observed facts from a proposed fix. Before destructive changes, establish target, scope and recovery. Verify the intended application result afterward, not just a successful command exit.

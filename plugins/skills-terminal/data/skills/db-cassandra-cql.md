Write Cassandra CQL or design a table around its partition and clustering keys.

## Inspect

Confirm cluster, keyspace, release, replication and the exact query pattern. Inspect the named table definition with the client's supported schema command or bounded `system_schema` queries. Identify partition keys, clustering order, types and TTL requirements before generating CQL.

## Query and design

CQL is not general relational SQL. Model a table for each required access pattern. A query normally needs an appropriate partition restriction; a final LIMIT does not make a cross-partition scan cheap. Do not add `ALLOW FILTERING` as an automatic repair. Explain the data scanned, partition size and consistency requirement instead.

Use prepared parameters for values and actual schema names. For a preview, select explicit columns from a known partition with a small limit and request timeout. Avoid arbitrary full-table counts.

## Change and verify

Table, replication, TTL and data changes are user-run operations. Check tombstone, retention and migration consequences first. Verify representative partition reads and application behavior. Changing a primary-key design usually needs a new table and migration; deleting the old table is a separate destructive decision.

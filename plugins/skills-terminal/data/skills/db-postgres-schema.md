Inspect PostgreSQL tables or plan a schema migration without inventing columns or losing data.

## Inspect

Confirm server version, database, schema and ownership. Read `information_schema.columns` for the named table: `SELECT column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema = '<schema>' AND table_name = '<table>' ORDER BY ordinal_position LIMIT 50;`. Substitute actual names, with SQL string escaping. Inspect its constraints and indexes. Return only relevant objects; a full schema dump may expose unrelated information.

## Plan

State the exact object and before/after type or constraint. Check existing NULLs, duplicates and values that cannot convert using bounded queries. Explain whether the proposed operation takes a lock, rewrites data, builds an index, or needs application changes. A small sample cannot establish that every row converts.

Do not bundle migration, data deletion and application deployment into one unexplained command. `CREATE INDEX CONCURRENTLY` has transaction restrictions and can leave an invalid index after failure; check the installed version and operation.

## Verify and recover

The user runs the reviewed migration. Check catalog state and a relevant application query afterward. Dropped columns or lossy conversions need a verified data backup; reversing the DDL cannot recover discarded values.

Write MySQL or MariaDB queries, inspect tables, or plan a schema change.

## Inspect

Confirm the server product/version and intended schema. Inspect the named table's columns, keys, collation and storage engine. Ask what one output row represents. Do not copy PostgreSQL syntax or assume both products support the same features.

## Query

Use explicit columns, parameters for values, a relevant filter and a small preview limit. Check join multiplicity and NULL handling. Use an account restricted to reads and `START TRANSACTION READ ONLY` where supported. A transaction cannot make every operation reversible: many DDL statements cause implicit commits.

## Change and verify

Show the exact schema or data change separately for the user to run. Inspect conversion failures, duplicate values and lock implications first. Check product-specific online-DDL support rather than promising a nonblocking operation. Verify the resulting schema and representative queries afterward. A reverse ALTER does not recover truncated values, removed columns or deleted rows; require a suitable backup before a lossy migration.

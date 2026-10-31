Write SQLite queries or inspect schema while keeping a live database intact.

## Inspect

Open the observed existing file with `-readonly`. Read the relevant table definition from `sqlite_schema` and use `PRAGMA table_info(<table>);` and `PRAGMA index_list(<table>);` with verified identifiers. Confirm `sqlite_version()` before relying on newer syntax.

## Query

Use explicit columns and a small `LIMIT` for previews. Explain SQLite's type affinity and how the actual stored values affect comparison, sorting and dates. Do not assume PostgreSQL or MySQL types and functions work here.

Start with `EXPLAIN QUERY PLAN` for a known read query. It describes the plan, not measured runtime. Use parameter binding for values when the calling tool supports it. Never interpolate untrusted values or execute extension-loading functions.

## Change and verify

Writes and migrations are user-run proposals. Check the existing schema and recovery copy first; some table changes require rebuilding a table. Verify constraints, row counts appropriate to the operation and application behavior after the change. A syntactically accepted migration is not evidence that the application still reads its data correctly.

Import CSV or other data into Neo4j without overwriting a live database or multiplying nodes.

## Inspect

Confirm Neo4j version, edition, target database, source format, headers, encoding and allowed source location. Inspect a small sample without private rows. Define stable node identifiers, relationship endpoints, property types and duplicate handling before choosing commands.

## Choose the route

`neo4j-admin database import` and Cypher `LOAD CSV` are different workflows. A full administrative import targets a suitable new/offline database; do not point it at the existing production store. Check the installed tool's help and documented format. `LOAD CSV` uses the server's file/network access, not the client machine's paths. Do not bypass the server's import restrictions.

## Verify and recover

Show a user-run import proposal with source/target, expected counts, transaction strategy and failure behavior. Use parameters and explicit conversions rather than concatenated Cypher. Test on an isolated database first. Check node counts, duplicate IDs, missing relationship endpoints, constraints and representative graph queries. Keep source files and a recovery copy; reversing node creation is not automatically safe after other writes.

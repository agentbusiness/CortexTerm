Neo4j slow Cypher queries, index state, constraints or execution-plan questions.

## Inspect

Confirm database/version and exact parameterized query. Inspect relevant index and constraint state with version-supported `SHOW INDEXES` and `SHOW CONSTRAINTS`, returning only needed columns and bounded rows. An index may still be populating or have failed.

## Interpret

Use `EXPLAIN` before executing a query. Inspect starting scans/seeks, estimated cardinality, joins, sorting and path expansion. `PROFILE` measures executed work; it must not be used automatically on an unknown write. A final LIMIT does not bound every earlier expansion.

## Change and verify

Propose one constraint or index tied to the actual lookup pattern and property types. Check duplicates/nulls before a uniqueness or existence requirement. Index creation changes the database and may consume resources. Do not delete existing indexes based on one plan.

After the user runs a change, verify that the intended index is online and inspect the same plan. Measure representative runtime separately when appropriate. An online index alone does not prove a faster application or correct query semantics.

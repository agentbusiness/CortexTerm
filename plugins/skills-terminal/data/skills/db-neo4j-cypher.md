Write or explain Neo4j Cypher using observed labels, relationship types and properties.

## Inspect

Confirm database and Cypher/server version. Obtain only relevant schema/index information and a small allowed sample. Use bounded known metadata procedures such as `CALL db.labels() YIELD label RETURN label LIMIT 20;` when available. Do not invent relationship direction or cardinality.

## Query

Use parameters for values. Explain the starting node pattern, relationship direction and output grain. Bound traversal depth and return rows; an unbounded variable-length path can explode even with a final LIMIT. Avoid returning whole private nodes when selected properties suffice.

A read procedure should contain only the intended read operations and known built-ins. `CALL` can invoke procedures with effects. A read access mode is routing guidance, not an authorization boundary.

## Verify

Start with `EXPLAIN` for a query-plan question. `PROFILE` executes the query, including writes. Check duplicate paths, optional-match nulls and join multiplication against the requested result. `CREATE`, `MERGE`, `SET`, `DELETE` and schema changes are separate user-run proposals with a reviewed scope and recovery route.

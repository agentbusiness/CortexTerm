Edit SQL, CQL, Cypher or MongoDB query text using the actual database language and schema.

Identify the engine, server version, target database and query language. SQL, Cassandra CQL, Neo4j Cypher and MongoDB pipelines are not interchangeable. Read a bounded real schema before writing names or types.

Use `config` inspect to read a saved UTF-8 query file. Use format `sql` for SQL and `text` for other dialects. The helper can preview a unique literal file change with its inspect hash; it does not validate or execute database statements.

Preserve parameters rather than embedding user data in query text. Limit read results. Distinguish a query file being saved from the query being run.

Use the product's plan or validation facility where suitable, checking whether it executes the statement. PostgreSQL `EXPLAIN ANALYZE` executes; some MongoDB aggregation stages write output. Transactions do not undo every external effect or every engine's DDL.

Offer writes, migrations and imports only as user-run actions with a bounded target and recovery plan. Verify the intended rows, schema or graph change from actual output; exit zero alone is insufficient.

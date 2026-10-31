Connect to Qdrant, Weaviate, Milvus or pgvector and inspect vector schema or authentication.

## Inspect

Identify the actual product/version, target endpoint, API/driver, tenant, collection or table, TLS and credential source. These systems have different APIs; do not treat every vector database as Qdrant. Check protected configuration without printing tokens.

Use the product's documented bounded health/metadata request. For Qdrant, a GET of `/collections/<observed-name>` can report collection configuration when authorized; filter the response to needed fields. For pgvector, inspect the PostgreSQL extension and relevant column/index definitions on the intended database. Bound HTTP connection/total time or database statement time.

## Interpret

Confirm vector names, dimensions, distance metric, index state and payload/filter schema. A healthy endpoint does not prove that the application uses the intended collection or embedding model. Named, sparse and multi-vector configurations need product-specific handling.

## Change and verify

Collection creation, credentials, schema and index changes are user-run proposals. Keep existing data intact. Verify the same identity/metadata request and a small authorized application query after correction. Never disable authentication or expose the service publicly to fix connectivity.

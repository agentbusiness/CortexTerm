Back up, restore, migrate or rebuild a vector database or embedding index.

## Inspect

Identify product/version, collection/table, embedding model/version, dimensions, vector names, distance metric, index/payload schema, source documents and tenant boundaries. Determine whether original text, metadata and embedding code are available. Vectors alone may not preserve the application's full knowledge store.

## Plan

Use the product's supported snapshot/export method for the exact deployment. Include schemas, filters, aliases and required access configuration. A local snapshot on the same disk is not an independent recovery copy. Changing embedding model or dimensions generally needs re-embedding; copying vectors cannot fix incompatibility.

## Change and verify

Backup/export writes files or objects. Restore, collection replacement, reindexing and re-embedding change state and consume resources. The user runs these steps against explicit targets. Prefer an isolated destination and preserve the source until the replacement is accepted.

Check counts appropriate to the scope, dimensions, metadata filters, access controls and known-example retrieval quality. Verify application references to the new target. A restored collection reporting healthy does not prove equivalent retrieval or restored source documents.

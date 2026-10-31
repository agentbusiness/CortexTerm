Vector search returns irrelevant, missing or dimension-mismatched results, or needs filter tuning.

## Inspect

Confirm product/version, exact collection, vector dimension/name, distance metric and embedding model/version. Compare query-time and ingestion-time normalization/preprocessing. Inspect a small allowed payload projection and index state. Never invent an embedding or assume vectors from different models are interchangeable.

## Query

Use the product's documented query API with a small result limit and bounded request time. Return only necessary identifiers, scores and allowed payload fields; do not return stored vectors by default. Verify filter names/types, tenant scope and hybrid-search configuration. An HTTP POST query may read data, but the risk engine decides whether it runs.

## Interpret and verify

A similarity score is not a probability of correctness. Different metrics and products order/scale scores differently. Evaluate against a few known relevant and irrelevant examples, keeping the same query and data. Separate missing ingestion, wrong filters, incompatible embeddings and approximate-index recall.

Changing models, dimensions, distance settings or indexes may require rebuilding data. Present that as user-run work with capacity, migration and recovery considerations.

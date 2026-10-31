MongoDB slow queries, missing indexes, inefficient aggregation or index changes.

## Inspect

Confirm server version, collection, exact filter/sort/projection and existing indexes. Inspect the relevant index definitions without exposing document values. Start with query-planner explain, for example `db.<collection>.find(<filter>, <projection>).limit(20).maxTimeMS(5000).explain("queryPlanner")`, after replacing names from observed schema.

## Interpret

Look at winning access paths, sort support and whether the filter can use an index. Execution statistics and all-plans execution run work; they are deliberate measurements, not free metadata checks. A collection scan can be reasonable for a small collection or broad query.

## Change and verify

Offer one index justified by the actual query pattern, including key order and write/storage costs. Check existing duplicates before a unique index, and array/multikey restrictions where relevant. Index creation is a user-run database change and can consume significant resources. Do not drop indexes just because a single query does not use them.

Compare the same query plan and measured workload afterward. Confirm index completion and application behavior; an accepted create request is not proof of a completed or beneficial build.

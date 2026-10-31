Build or explain a MongoDB aggregation pipeline, lookup, grouping or array transformation.

## Inspect

Confirm collection, field types, indexes and the requested result grain. Read a small permitted projection of source documents. Distinguish missing fields from nulls and arrays from single values.

## Build

Explain each stage in order. Put selective `$match` stages early when semantics permit. Use explicit projections, check `$unwind` row multiplication, and state how `$lookup` changes missing matches. Example shape: `db.<collection>.aggregate([{$match:<filter>}, {$group:<group>}, {$limit:20}], {maxTimeMS:5000, allowDiskUse:false})`. Replace each part from the requested result and observed schema. Add the preview limit at the end; do not silently put a sampling limit before a grouping stage, because that changes totals.

A diagnostic pipeline must not contain `$out`, `$merge`, `$where` or unknown executable behavior. Allowing disk use and running a large aggregation are operational decisions; do not assume output limits bound server work.

## Verify

Use query-planner explain first when performance matters. Runtime execution statistics execute the pipeline. Compare expected grouping and join behavior with a small known subset. Label sampled results as samples. Write-output stages need a separate reviewed user-run change and recovery plan.

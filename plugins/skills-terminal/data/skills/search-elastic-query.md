Write Elasticsearch or OpenSearch queries, inspect mappings or diagnose slow searches.

## Inspect

Confirm product/version, target index or alias, mapping, relevant fields and permitted data scope. Inspect only the needed mapping and a small explicitly allowed projection. A text field and a keyword field support different matching and aggregation behavior.

## Query

Use a small `size`, explicit `_source` fields and an appropriate query timeout. Filters, full-text matches, date/time zones and nested documents have different semantics. Do not invent fields, choose a new embedding model or silently query every index. Avoid expensive wildcard/scripted operations unless the task and evidence justify them.

A POST search request can be read-only at the API level; the risk engine still decides whether it may run. Do not disguise it as GET or bypass a refusal.

## Change and verify

Mapping changes, index creation, reindexing and alias swaps are user-run changes. Some field-type changes require a new index and migration. Verify query meaning on a known subset, then measure representative runtime separately. A syntactically valid DSL request is not proof of accurate search results.

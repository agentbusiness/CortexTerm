Write MongoDB find queries using actual document fields, BSON types and bounded output.

## Inspect

Confirm database and collection. Obtain collection validation/schema information and an explicitly allowed small projection of sample documents. Records may contain private data; do not dump whole collections. A sample shows observed shapes, not every possible field or type.

## Query

Use a specific filter and explicit projection. For a preview, append `.limit(20).maxTimeMS(5000)` to a `find` query. Include `_id:0` when the user does not need identifiers. Match actual BSON types: a string, date, ObjectId and number are not interchangeable. Do not invent fields or transform a literal into JavaScript code.

Avoid `$where`, server-side JavaScript and unknown functions. A small result limit does not make a whole-collection scan cheap. Use the index/planning skill when the query is slow.

## Verify

Explain expected matches, missing fields, arrays and NULL behavior. Check that the projection and filter answer the requested question. Inserts, updates and deletes are separate user-run proposals; inspect their match scope and recovery route before offering them.

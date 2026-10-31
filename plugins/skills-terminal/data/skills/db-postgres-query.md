Write or explain a PostgreSQL SELECT query using the real schema and bounded results.

## Inspect

Confirm the database and role. Read only the relevant tables, columns, types, indexes and relationships. Ask for the desired result grain: one row per customer, order, day, or another entity. Do not invent names or treat a sample as the complete dataset.

## Query

Use explicit columns, qualified schema names and a deterministic `ORDER BY` when order matters. Add a small `LIMIT` for previews. Parameterize values; identifiers need identifier quoting, not string quoting. Explain how joins affect row counts and how NULL differs from an empty string.

For inspection, use a role with read privileges and a read-only transaction with a short `statement_timeout`. Read-only does not make a large scan cheap. Never execute unknown functions, extensions or a data-changing CTE as a diagnostic SELECT.

## Verify

Check output types, duplicate rows and unmatched joins. Compare a bounded result with the requested meaning. Offer writes separately; a syntactically valid query is not proof that its answer is correct.

Import or export CSV, TSV, JSON Lines or database dumps with correct types and scope.

## Inspect

Confirm source/destination engines and versions, table/collection, file size, encoding, delimiter, header, NULL representation and date/time zone. Inspect a small permitted sample, not the whole private file. A CSV value containing a newline can span several physical lines.

## Plan

Use the engine's supported bulk tool. Distinguish a client-side file path from a server-side path. Decide explicit columns/types, duplicate handling, transaction or batch boundaries, failed-row reporting and space requirements. JSON exports may not preserve engine-specific types, indexes, users or constraints.

## Execute and verify

Imports and exports write data or files; present the exact scoped user-run proposal. Import into a staging table or isolated target when possible. Avoid replacing production objects or enabling executable extensions as a shortcut. Protect output files and credentials.

Check accepted/rejected row counts, conversion errors, types, constraints and representative values. Row-count equality alone does not establish correct mappings or joins. Keep original source and target recovery copies until the user accepts the result.

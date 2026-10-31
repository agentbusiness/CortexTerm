Inspect Redis or Valkey key types, TTLs, lists, hashes, sets or streams without dumping data.

## Inspect

Confirm server and selected database. Use `TYPE <key>`, `TTL <key>` and structure sizes such as `LLEN`, `HLEN`, `SCARD` or `XLEN` for a named observed key. Key names can themselves be private; restrict the scope.

## Read bounded data

Prefer metadata. When values are needed and allowed, use a small range/projection appropriate to the type. To discover a narrow key pattern, use a single `SCAN 0 MATCH <pattern> COUNT 10` call and retain its cursor. COUNT is a work hint, not a strict output bound; SCAN may return duplicates and does not represent a stable snapshot. Do not automatically iterate the whole keyspace.

Avoid `KEYS *`, unrestricted `HGETALL`, full-list ranges and blocking subscriptions. Do not consume queue/stream entries as a read-only check.

## Change and verify

SET, deletion, expiration changes, list pops and consumer acknowledgements change data. Offer them separately for the user with an exact key scope. Verify type, TTL and intended application behavior afterward; an accepted write does not prove the correct database was selected.

Read, validate or edit JSON Lines and NDJSON: one complete JSON value per line.

## Inspect

Establish the consumer and the actual file. JSONL/NDJSON is not a JSON array or CSV. Each record is a complete JSON value on one physical line; strings contain escaped newlines. A final newline is allowed. A blank record is invalid for this helper. Do not assume every record has the same fields or types.

Use `config` inspect with format `jsonl` and a bounded section. The helper checks each record independently, rejects duplicate keys and non-finite numbers, and returns a line location without copying parser input. Secret-like fields remain hidden. An oversized file belongs in the viewer or a bounded record-processing workflow; do not load it all into context.

## Change and verify

For one non-secret correction, use preview with the inspected hash and one exact old/new match. Preserve record boundaries. Never replace every matching value across the stream. Changing a schema may require a migration of the consumer and other records; a valid JSON record does not prove compatibility.

After the person applies the reviewed proposal, validate the file again and exercise the consumer on the affected record. Preserve the original import or log before a larger conversion. Follow the consumer's documented rules when it accepts a different NDJSON dialect.

Create or restore a file or service backup and verify that it is usable.

## Inspect

Establish what must be recovered, its owner, current activity, destination, retention and available space. A live database or application may need a native consistent backup; copying its active files is not automatically valid. Identify required configuration, data, uploads, keys and product versions without exposing secret values.

## Propose

Use the existing backup tool and an explicit destination. Explain whether the operation reads, writes, pauses a service or overwrites data. Protect backups as sensitive data. Do not prune older copies until a replacement is saved and verified.

For restoration, choose an isolated destination or planned maintenance window. Confirm the exact backup and target before replacing live content. Restoring application files alone may mismatch a newer database schema.

## Verify

Check backup completion, readability and expected content. A checksum confirms bytes, not recoverability. Perform an authorized isolated restore and the relevant application checks before calling a backup proven. Record which restore was exercised and what remains unverified. Keep the original live state until the recovery is accepted where feasible.

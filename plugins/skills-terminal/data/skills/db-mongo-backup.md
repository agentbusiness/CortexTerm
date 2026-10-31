Back up MongoDB, restore BSON data, or plan a deployment upgrade.

## Inspect

Confirm deployment type, server version, Database Tools version, database scope and restore target. Distinguish BSON dumps from JSON exports; exports do not preserve every BSON type, index or database feature. Determine required consistency, encryption and credentials.

## Backup

Choose the deployment's supported backup method. A live `mongodump` needs a consistency plan; do not promise a consistent distributed snapshot merely because it completed. Oplog-based options have deployment and scope restrictions. Check matching official guidance for the actual topology before proposing flags. Creating a backup is a user-run operation.

## Restore and verify

Restore into a separate compatible deployment first. Do not add `--drop` or target production by default. Validate namespaces, BSON types, required indexes, access controls and representative application queries. Keep secrets out of command arguments and protect backup files.

For upgrades, inspect the supported version path and feature compatibility version. Do not skip required releases or change feature compatibility before rollback implications are understood. A dump file is not proof that recovery works.

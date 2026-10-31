Install Kafka or inspect an existing Kafka deployment, KRaft quorum and storage layout.

## Inspect

Confirm target OS, architecture, Kafka release, supported Java, deployment method, memory/disk and whether data already exists. Find installed CLI paths with the service/package rather than assuming a download directory. Use version/help commands from that installation.

## Set up

Use the chosen release's documented KRaft setup for a new deployment. Older clusters may have a different coordination history; do not apply new-cluster initialization to them. Determine controller/broker roles, node IDs, quorum configuration, log directories, listener addresses and security before startup.

Storage formatting creates cluster metadata. It is a separate user-run initialization step for verified new storage, not a repair for an existing cluster. Never invent a new cluster ID over existing data or erase log directories to force startup.

## Verify

Inspect bounded startup errors, quorum status with release-supported tools and broker metadata from the intended client network. Confirm advertised endpoints, topic access and a deliberate user-run message check when appropriate. A running Java process or open bootstrap port alone does not prove that Kafka clients can use the cluster.

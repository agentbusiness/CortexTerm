Cassandra read/write timeouts, tombstones, large partitions, compaction pressure or slow CQL.

## Inspect

Get the exact operation, keyspace/table, partition restriction, consistency level and failure interval. Inspect bounded node metrics/logs. Where allowed, use the release-supported `nodetool tablestats <keyspace>.<table>`, `nodetool tablehistograms <keyspace> <table>` and `nodetool tpstats`; each can exceed the assistant deadline on a troubled node.

## Interpret

Separate unavailable replicas from slow work, dropped messages, saturated disk and client timeouts. Inspect replication and node state before changing consistency. A small output LIMIT does not prevent expensive scans or tombstone processing. Do not add `ALLOW FILTERING`, raise every timeout or disable safeguards without evidence.

## Change and verify

Propose one correction tied to the observed bottleneck: query pattern, partition design, client concurrency or a documented operational setting. Compaction, repair and schema/data changes consume resources and are user-run work. Compare the same workload, error rate and relevant metrics afterward. A longer timeout hiding errors is not proof that the underlying capacity problem is solved.

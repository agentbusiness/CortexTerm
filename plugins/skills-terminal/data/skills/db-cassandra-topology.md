Cassandra nodes disagree, fail to join, use wrong addresses, seeds or datacenters, or lack quorum.

## Inspect

Confirm cluster/release, datacenters, replication, node identities and actual network paths. Run bounded `nodetool status` and `nodetool describecluster` when existing JMX authentication permits. One node's view is not the whole cluster; compare affected nodes when needed. Read only relevant non-secret address, seed and snitch settings.

## Interpret

Distinguish listen, broadcast, client/native-transport and JMX addresses. Seeds help discovery; changing seeds is not a general replication repair. Datacenter names must match replication configuration. Inspect version-specific configuration: do not copy older RPC settings into a newer release without checking support.

## Change and verify

Adding/replacing nodes, changing topology, replication and snitch configuration are planned user-run operations. Identify quorum, streaming state, backups and failure consequences before proceeding. Never reuse an old node identity or wipe data simply to force a join. After a documented action, inspect status from multiple relevant nodes, schema agreement, streaming progress and representative reads/writes. State any missing JMX or node access.

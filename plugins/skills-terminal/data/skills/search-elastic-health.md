Elasticsearch or OpenSearch cluster health, unassigned shards, startup or connectivity failures.

## Inspect

Confirm product/version, cluster endpoint, TLS, account and intended index. Use protected existing credentials and bounded HTTP checks: `curl --connect-timeout 3 --max-time 10` with the observed endpoint and certificate options. Never include passwords in generated arguments or disable TLS verification.

Inspect selected health fields, for example `/_cluster/health?filter_path=status,number_of_nodes,active_shards,unassigned_shards`. For an affected index, inspect its shard state using version-supported selected fields. Do not dump the entire cluster state or private documents.

## Interpret

Yellow commonly concerns replica allocation; red concerns unavailable primary shards. The color is a symptom, not a cause. Inspect allocation decisions, disk watermarks, node availability and version compatibility before proposing changes. Product APIs differ; do not assume Elasticsearch and OpenSearch releases are interchangeable.

## Change and verify

The user runs allocation, restart, setting and index changes. Never delete indices or data directories merely to clear health errors. Recheck named-shard availability and the original application query after the agreed correction.

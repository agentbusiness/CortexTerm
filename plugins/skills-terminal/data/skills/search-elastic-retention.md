Elasticsearch or OpenSearch disk growth, index retention, snapshots, restore or reindexing.

## Inspect

Confirm product/version, affected index/alias, storage usage, shard count, retention policy and recovery objective. Inspect the named policy and snapshot state with bounded selected fields. Elasticsearch lifecycle management and OpenSearch index-state management differ.

## Plan

Separate deleting documents, deleting an index, closing it, force merging and changing future retention. A retention update cannot restore already removed data. Reindexing needs destination capacity and mapping/settings decisions. Force merge and shard operations can be expensive; they are not read-only cleanup.

## Backup and change

Use a supported snapshot repository and verify snapshot completion. A filesystem copy of a live data directory is not the standard recovery method. The user runs repository setup, snapshots, lifecycle changes, reindexing and restores. Keep credentials protected and avoid broad wildcard deletions.

## Verify

Restore into isolated names first. Check aliases, mappings, index counts, required permissions and representative application queries. Keep source indices and snapshots until the new target is accepted. Cluster health alone does not establish that the expected data and search behavior were recovered.

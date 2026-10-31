Work with S3-compatible object storage, permissions, transfers and backup repositories.

## Inspect

Establish provider, endpoint, region, account, bucket and exact prefix. Use the existing CLI and profile. Bound listings and avoid printing object contents, access keys or signed URLs. An S3-compatible endpoint may require different addressing and region conventions from AWS.

Inspect the intended operation's error: authentication, authorization, wrong region, missing object and network failure differ. Check bucket versioning, retention and lifecycle settings when recovery matters. An object listing does not establish permission to read, write or delete it.

## Propose

Uploads, syncs, lifecycle changes and deletions are user-run operations. Preview source/destination and deletion scope. Do not add a sync deletion flag or recursively remove a prefix without explicit intent. Protect backup keys and preserve a verified prior recovery point before pruning.

## Verify

Check object size, suitable integrity metadata and the intended application read. Multipart ETags are not always a simple file MD5. For backup tools such as restic or Borg, verify their repository and restore workflow rather than treating raw object presence as a usable backup. Test recovery in an isolated destination when authorized.

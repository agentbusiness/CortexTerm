Diagnose disk-full errors, inodes, mounted volumes or open deleted files.

## Inspect

Read the exact failing path and error. Use `df -h '<path>'` to find its filesystem. On Linux, `df -i '<path>'` checks inode exhaustion; `lsblk -f` can show block devices when available. On macOS, `diskutil info '<volume>'` and APFS-aware information may help. Do not assume `/` is the data volume.

Compare filesystem usage with bounded `du` results in the relevant folder. Differences can come from snapshots, sparse files, reserved space, permissions or deleted-but-open files. `lsof +L1` can identify unlinked open files when supported and permitted.

## Propose

Identify the owning service before changing storage. Do not delete database files, journals or snapshots without understanding their recovery role. Formatting, partitioning, remounting and filesystem repair require a specific product procedure and deliberate user action.

## Verify

Check the same filesystem and repeat the failed write or operation after the agreed fix. Free space alone does not establish filesystem health. Preserve the exact error if permissions or a read-only mount remains the cause.

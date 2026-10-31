Copy folders with rsync, scp or SFTP and explain transfer direction and exclusions.

## Inspect

Establish source machine, destination machine, exact paths, authentication and available space. Check `rsync --version`; the system macOS copy may differ from current Linux versions. For SSH transport, inspect the selected host's effective configuration and identity without printing private keys.

## Propose

Start with the installed rsync's dry-run mode, for example `rsync -an --itemize-changes '<source>/' '<destination>/'`. A trailing slash changes whether the directory itself or its contents are copied. Explain that difference using the actual paths.

Review exclusions, ownership, permissions and symlink handling. `--delete` removes destination entries; offer it only when that removal is explicitly intended and recoverable. Do not add it merely to make two folders look alike. Remote transfers use the target's path rules.

## Verify

After the person runs the transfer, check expected files and relevant metadata. For important data, verify content with a suitable comparison or checksum. A successful transport does not prove a database backup was consistent. Keep the source until verification and any agreed retention period are satisfied.

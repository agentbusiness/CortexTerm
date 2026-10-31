Create, copy, move or rename specific files while avoiding accidental overwrites.

## Inspect

Use `pwd` and `ls -ld '<source>' '<destination>'` for the observed paths. Establish whether the destination exists, is a directory, or is a symlink. Inspect the destination parent and available space when copying large data. Quote each path separately; never build a changing command from an `ls` listing.

## Propose

Give one command for the person's chosen action: `mkdir`, `cp` or `mv` with exact paths. Use the installed tool's no-overwrite or interactive option when appropriate, and explain what an existing destination would mean. A cross-filesystem move may copy and then remove the source; it is not always an instant rename.

Do not replace an existing file unless the person intended that replacement. Keep important metadata or a recovery copy when required. For edits to a text configuration, use `config` preview rather than replacing its whole contents.

## Verify

After the command runs, inspect both expected locations. A successful copy is not proof the application uses that copy. For important backups, compare content or a suitable checksum before removing the original.

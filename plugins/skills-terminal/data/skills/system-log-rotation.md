Diagnose growing log files, missing logs or rotation and retention settings.

## Inspect

Find the log owner, path, size, growth rate and available storage. Inspect the relevant application's logging configuration and existing rotation mechanism. On Linux, check the matching logrotate definition or journal retention. On macOS, identify the application's logger rather than treating unified logs as plain files.

Read a bounded recent section and filter credentials. A process can keep writing a renamed or deleted file through an open descriptor; inspect with `lsof` when appropriate. Removing the filename may not release its space until that descriptor closes.

## Propose

Choose retention and size limits according to the person's needs. Preview configuration changes and use the product's supported reopen or rotation method. Truncating or deleting active logs loses evidence; do not offer it as the default cleanup. Preserve incident evidence before retention changes.

## Verify

Check new log output, the rotated file and storage after a rotation cycle. A rotation command exiting zero does not prove the application reopened its file. Keep the old settings for recovery and report the actual retained interval.

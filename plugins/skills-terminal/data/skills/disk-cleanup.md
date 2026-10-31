Find what fills a disk and choose exact cleanup targets without losing needed data.

## Inspect

Use `df -h '<affected path>'`; on macOS also distinguish the Data volume. Start in the relevant folder with a supported one-level `du` command, such as `du -h -d 1 '<folder>'`, then inspect the largest child. Bound each search. Permission errors and excluded paths limit the result.

Check known build output, caches, downloads and container storage separately. `docker system df` explains Docker's view. A cache can contain costly downloads or offline material; build output may be the only retained artifact. Do not call all caches safe to delete.

If `df` and `du` disagree, inspect snapshots, sparse files and deleted-but-open files before removing more data. Databases need product-specific retention and backup procedures.

## Propose

List exact paths, sizes, ownership, what is lost and how it could be recovered. The person chooses and runs cleanup. Preserve live data, active model files, repository history and a verified recovery copy. Use the OS's supported Trash mechanism for recoverable personal files; `~/.Trash` is not portable Linux trash.

## Verify

Measure the same filesystem afterward and repeat the failed operation. Do not claim a cleanup ran because it was suggested.

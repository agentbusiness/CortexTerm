List files, hidden entries, sizes and dates without reading their contents.

## Inspect

Use `ls -lah '<folder>'` for a small known folder. For a large folder, show a bounded selection and say that the listing is incomplete. `ls -ld '<path>'` shows the path itself rather than its contents. Quote literal names and use `--` where the installed tool supports it for names beginning with a dash.

Explain only relevant fields: type, permission bits, owner, group, size and modified time. Directory size in `ls` is not the sum of its files; use `du -sh '<folder>'` for allocated usage. A symlink's arrow names its target.

## Interpret

Hidden names begin with a dot. A recent modified time does not prove who changed a file. Human-readable sizes are rounded. `ls` output is for people, not a reliable list to feed back into changing shell commands.

If the person wants a change, name the exact entries and action. Verify the resulting paths afterward. Do not delete hidden files merely because their purpose is unfamiliar.

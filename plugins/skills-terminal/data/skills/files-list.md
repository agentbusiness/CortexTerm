List files, hidden entries, sizes and dates without reading their contents.

## Inspect

For names only, run `ls -1Ap '<folder>'` once: one name per line, and a folder ends with `/`. Do not run it again through `grep` or `awk`; that output already answers the question. Use `ls -lah '<folder>'` only when sizes, dates or owners matter. For a large folder, show a bounded selection and say that the listing is incomplete. `ls -ld '<path>'` shows the path itself rather than its contents. Quote literal names and use `--` where the installed tool supports it for names beginning with a dash.

Explain only relevant fields: type, permission bits, owner, group, size and modified time. Directory size in `ls` is not the sum of its files; use `du -sh '<folder>'` for allocated usage. A symlink's arrow names its target.

## Answer

Start with the count, such as "14 folders, plus 43 hidden ones". Then list the names one per line, each line starting with `- `. Never run many names together in one comma-separated paragraph.

With more than 20 names, list the visible ones. Group the hidden ones by what they belong to, one line per group, such as `- Rust: .cargo, .rustup`. The full listing stays in the check above the answer.

## Interpret

Hidden names begin with a dot. A recent modified time does not prove who changed a file. Human-readable sizes are rounded. `ls` output is for people, not a reliable list to feed back into changing shell commands.

If the person wants a change, name the exact entries and action. Verify the resulting paths afterward. Do not delete hidden files merely because their purpose is unfamiliar.

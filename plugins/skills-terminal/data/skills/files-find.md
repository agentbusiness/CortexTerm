Find a file by name, extension, size or date within a known folder.

## Inspect

First establish the search root and what is known about the file. Prefer `rg --files --hidden -g '!**/.git/**' '<root>'` when ripgrep exists; it obeys ignore rules unless asked otherwise. Match names with `rg -i '<pattern>'` and limit displayed results. State when ignored or inaccessible files were excluded.

Without ripgrep, check `find --help` or the local manual for supported options. Start within one known folder and use a supported depth bound. Example: `find '<root>' -maxdepth 4 -type f -name '*.toml'` on a tool that supports `-maxdepth`.

## Interpret

No matches means none within that search scope and access, not that the file does not exist anywhere. Check spelling, case, symlinks and hidden files before broadening the root. Date and size flags differ between implementations; inspect the local syntax.

Keep discovery read-only. Do not add `-delete`, `-exec` or a pipe into removal. Show exact candidate paths before proposing any action.

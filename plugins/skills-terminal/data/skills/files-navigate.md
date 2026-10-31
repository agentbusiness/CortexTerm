Find the current folder and explain absolute paths, relative paths, home and parent folders.

## Inspect

Use `run` with `pwd`; use `ls -ld . ..` if the location or access is unclear. A Run's folder and a shell's current folder may differ. Use the selected terminal's facts, not a remembered project path.

An absolute path starts at `/`. `~` means the current user's home. `.` is this folder; `..` is its parent. Quote paths with spaces. A symlink can make the displayed path differ from its physical location; `pwd -P` shows the physical path.

## Next step

For navigation, give the person `cd '<observed path>'`. It changes their shell; a `cd` inside `run` does not move that shell. Do not expand a guessed project name into a path.

After they change folders, use fresh terminal state or `pwd` to confirm the location. If access fails, read the exact error and inspect parent permissions; do not suggest recursive permission changes.

The disk is full or nearly full; what takes the space and what is safe to delete.

## Find what takes the space (with `run`)

1. How full: `df -h /` (macOS: also `df -h /System/Volumes/Data`).
2. The biggest folders in home: `du -h -d 1 ~ 2>/dev/null | sort -rh | head -15`. Then go one level into the biggest, again and again. Big folders take a while: one level at a time keeps it under 20 seconds.
3. The usual places, each with `du -sh <path> 2>/dev/null`:
   - `~/Library/Caches`, `~/Library/Developer/Xcode/DerivedData`, `~/Library/Developer/CoreSimulator`
   - `~/Library/Containers/com.docker.docker` (Docker Desktop's disk; `docker system df` says what is inside)
   - `$(brew --prefix)` and `~/Library/Caches/Homebrew`
   - `~/.npm`, `~/.cache`, `~/.cargo/registry`, `~/.gradle/caches`, `~/.m2`, `~/Library/Caches/pip`
   - `node_modules` and build folders: `find ~ -maxdepth 5 -name node_modules -type d -prune 2>/dev/null | head -20`
   - Downloads and the Trash: `du -sh ~/Downloads ~/.Trash`
4. Big single files: `find ~ -type f -size +1G 2>/dev/null | head -20`.

Report sizes as a short list, biggest first, and say for each what it is.

## What is safe (theirs to run)

Safe, they come back when needed: caches and build output.
- `brew cleanup -s`
- `rm -rf ~/Library/Developer/Xcode/DerivedData/*`
- `xcrun simctl delete unavailable`
- `npm cache clean --force`, `pip cache purge`
- `docker system prune` (see the docker skill for `-a` and `--volumes`)
- `node_modules` of projects they no longer work on (`npm install` brings it back)

Never suggest deleting: anything in `/System` or `/Library` they do not know, `~/Library/Application Support` of an app they use, `~/Library/Mobile Documents` (iCloud), Photos or Mail data, `.git` folders. For their own files (Downloads, videos, old installers), list them and let them choose.

Prefer moving to the Trash (`mv <path> ~/.Trash/`) for anything that is not a cache, so it can be undone.

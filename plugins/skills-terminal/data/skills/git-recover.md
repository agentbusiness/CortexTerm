Recover a Git change, deleted tracked file or lost commit before destructive cleanup.

## Inspect

Use `git status --short --branch`, relevant diffs and `git reflog -10 --date=iso`. Establish whether the missing content was committed, staged, unstaged or untracked. Git may not hold untracked or never-saved content. Do not promise recovery without finding a copy.

Inspect a candidate commit with `git show --stat <observed-id>` before proposing restoration. Protect current local work; restoring an old file can overwrite a newer edit. A reflog entry may belong to a different operation than the one being recovered.

## Propose

Prefer a new recovery branch for a found commit or a path-scoped restore from a verified source. Explain exactly what will be replaced. Never default to `reset --hard`, `clean -fd`, force-push or deleting Git's metadata. Confirm destructive replacement before it runs.

## Verify

Compare restored content to the intended source and inspect remaining status. Preserve the recovery branch or copy until the person confirms the content. Hand code-level reconciliation to CortexCode rather than guessing which version is correct.

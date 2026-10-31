Explain a Git merge, pull or rebase conflict while preserving unrelated local work.

## Inspect

Use `git status` and `git diff --name-only --diff-filter=U`. Identify whether a merge, rebase or cherry-pick is in progress. Read the conflict in its actual file and relevant history. Do not assume ours and theirs mean the same sides during merge and rebase.

Do not start another pull or rebase while the current operation is unresolved. Preserve unrelated work and do not reset or clean to remove a conflict. A conflict marker is a decision point about intended behavior, not a request to pick one entire side.

## Propose

Hand code conflict resolution to CortexCode with the operation, paths and intent. For a simple non-code configuration, use a reviewed scoped edit. Stage only resolved paths. Give the matching continue or abort operation only after explaining its effect on this operation.

## Verify

Inspect status and remaining unmerged paths after the person runs the next step. Confirm the operation finished and review the resulting diff. No conflict markers is not proof the merged application behaves correctly; preserve the repository's real verification workflow.

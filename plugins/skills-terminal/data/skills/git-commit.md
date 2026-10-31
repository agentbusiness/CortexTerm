Create a Git branch, stage selected changes or make a local commit.

## Inspect

Use `git status --short --branch`, inspect relevant diffs, and establish the current repository. Identify which changes belong to the requested work. Existing local edits may be unrelated. Check the intended branch and whether staged content already exists.

## Propose

Give user-run commands scoped to named files. Avoid `git add .` when unrelated files are present. A commit records exactly the staged content; unstaged edits remain outside it. Do not use `--amend`, force updates or history rewriting unless that is the requested action.

Choose a clear message describing the concrete change. Hooks may execute project code and the commit may fail; a proposed commit is not a completed commit. A new branch should follow the repository's naming rules.

## Verify

After the person runs it, read the result and inspect the new commit summary and remaining status. State whether the change is only local. Do not push merely because a commit succeeded. Hand source implementation to CortexCode on the machine containing the repository.

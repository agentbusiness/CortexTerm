Explain Git status, diffs, history or the current branch without changing the repository.

## Inspect

Use `git status --short --branch` and `git diff --stat` in the observed repository. Inspect only relevant paths with `git diff -- '<path>'`; staged changes use `git diff --cached`. For history, `git --no-pager log -10 --oneline` avoids an interactive pager.

Distinguish working-tree changes, staged changes, untracked files and committed history. A clean working tree says nothing about whether code builds or runs. Generated files and ignored files may not appear in ordinary status.

## Explain

Describe the actual changed behavior or file content, not just added-line counts. Do not attribute a local edit to yourself or another contributor without evidence. If the person asks what changed since a release, establish the exact reference before comparing.

Keep inspection read-only. Do not fetch, reset, clean, checkout or restore to make the output easier to read. If a diff contains credentials, redact them and flag the exposure without repeating the values. Hand code review or repairs to CortexCode when needed.

Find a previous command without exposing passwords, tokens or private shell history.

## Inspect

Start with the current conversation and recorded Runs. They include the working folder and result, which raw history may lack. Search a narrow command family and recent window. Do not print the whole history or scan other users' history.

History can contain credentials in URLs, headers, assignments and command arguments. Filter secrets before any output reaches the model. If a safe filter is unavailable, ask for a nonsecret command fragment or inspect only command names. Never reproduce a credential in an answer.

## Reuse

Treat a historical command as evidence of what was entered, not proof it remains appropriate. Check its target, directory, options and current version before offering it. History expansion can execute a different command than expected; give the explicit reviewed command instead.

If a credential was exposed, recommend replacement through its provider before deleting history entries. History deletion does not revoke a key or remove copies from logs and backups. Any changing command remains the person's proposal to run.

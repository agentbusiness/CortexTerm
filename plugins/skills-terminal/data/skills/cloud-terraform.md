Review Terraform or OpenTofu configuration, workspace, state context and a proposed plan.

## Inspect

Identify the tool and version, repository, backend, workspace, variable sources and provider lockfile. Inspect relevant configuration without printing secrets or raw state. State and saved plans can contain credentials even when the terminal hides sensitive values.

Read the existing plan output or propose a user-run plan for the exact target. Planning queries providers, may lock state and can execute configured data sources; it is not a harmless text parse. Initialization downloads plugins and writes local state. Do not run either automatically as a read-only check.

## Interpret

Explain actual adds, changes, replacements and destruction. Distinguish in-place change from replacement. Check account and region. Unknown values and provider drift limit what the plan establishes. Do not use targeted planning or refresh suppression to hide unrelated differences.

## Propose and verify

Apply only the reviewed saved plan or the person's chosen workflow. Do not use auto-approve or force-unlock as a generic fix. Verify resource state and service behavior after application. A successful apply does not prove application health; a configuration rollback does not necessarily recover deleted data.

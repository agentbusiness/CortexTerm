Deploy an application update or roll back a release while tracking data compatibility.

## Inspect

Identify the current and intended release, target, deployment mechanism and actual health. Read release notes and migration requirements for the installed version. Inspect pending local changes and required artifacts. A previous successful deployment is not evidence about the current target state.

Separate code, configuration, schema, uploads and other persistent data. A code rollback can fail after an incompatible migration. Check backup and restoration evidence before a change that can require data recovery.

## Propose

Use the platform's existing release workflow. Give a complete ordered runbook when requested, otherwise the next bounded user-run action. Explain downtime, migration order, health conditions and recovery choice. Do not rerun an interrupted deploy until its actual outcome is known.

## Verify

Confirm the target's release identity, startup, dependencies and representative user operation. Report deployment completion separately from live verification. If health fails, use the prepared product-specific recovery path; do not claim a restored image reverted external resources or database changes.

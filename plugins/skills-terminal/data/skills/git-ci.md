Find the failing stage in CI or a deployment pipeline and separate it from local state.

## Inspect

Use the exact workflow, run, revision, job and failing step. Read a bounded log section around the first decisive error. Inspect the matching pipeline file at that revision; the current working copy may differ. Mask secrets and signed URLs.

Separate runner setup, dependency installation, build, checks, artifact publication and deployment. Inspect the runner OS, architecture and relevant tool versions. A local success does not prove the remote runner has the same environment or secrets.

## Propose

Hand source or pipeline-code changes to CortexCode with the failing revision and evidence. Do not disable checks, widen credentials or rerun a production deployment as a generic repair. Determine whether a retry will publish, migrate data or redeploy before proposing it.

## Verify

A rerun belongs to a specific revision. Confirm which stages completed and whether a deployment reached the intended environment. Successful CI is not live application verification. For partially applied deployments, inspect the target's current release and data state before any retry or rollback.

Check the cloud account, subscription, project, region and active identity before a cloud task.

## Inspect

Identify the existing CLI and named profile. Do not print credential files, tokens or all environment variables. For AWS, `aws sts get-caller-identity --output json` identifies the active principal when the network call is allowed. For Azure, select only subscription name/id and tenant from `az account show`. For Google Cloud, inspect the selected account, project and region with the installed gcloud config queries.

A local profile name is not proof of its remote identity. An assumed role, expired session, environment credential or alternate configuration directory can change the result. Account, region and Kubernetes context are separate selections.

## Propose

Bind later commands explicitly to the intended profile, subscription/project and region using that CLI's supported options. Changing defaults or signing in is the person's action. Do not solve permission errors by granting broad administrator access.

## Verify

Repeat the identity query after an intended switch and inspect one named resource in the expected scope. Mask sensitive identifiers when sharing outside the task. If access is denied, state which operation failed and what remains unknown; do not infer a resource is absent.

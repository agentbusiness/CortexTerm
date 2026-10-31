Deploy or diagnose Dify, Flowise or Langflow components, providers, workers and stored data.

## Inspect

Identify the actual application, release and supported deployment method. These products do not share one recipe. Read the installed Compose files or package configuration and that release's supported dependencies. For Compose, list services, inspect status and use `logs --tail=40 <service>` for the failing component.

Trace the failing operation through UI/API, provider, worker, database and any vector store. Inspect relevant settings without exposing keys, prompts or documents. Check whether the configured model and embedding names actually exist. A container's localhost is not the host or another service.

## Propose

Preview one config change or give one documented user-run lifecycle step. Preserve persistent data, application secrets and release compatibility. Do not start another local model when the existing holder can serve the application. Do not reset volumes or reinstall the stack as the first repair.

## Verify

Exercise the original bounded workflow and inspect its resulting trace or job state. Separate provider generation from ingestion and retrieval. A running stack is not a working workflow. Establish backup and migration recovery before an update; keep the previous release until verification.

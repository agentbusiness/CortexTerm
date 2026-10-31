Deploy or diagnose n8n workflows, webhooks, proxy URLs, credentials and queue workers.

## Inspect

Identify n8n version, deployment method, public URL and execution ID. Inspect bounded logs for that execution and relevant component status. Do not print stored credentials or private workflow payloads. Establish whether the deployment uses a database, queue workers and task runners, using its actual configuration.

For a webhook behind a proxy, compare the external scheme/host/path with generated URLs and forwarded headers. The webhook setting is version-dependent: current releases use `N8N_WEBHOOK_URL`, while older releases use `WEBHOOK_URL`. Check the installed release's guide before editing. Trust only the actual number of proxy hops.

## Propose

Preview relevant settings and preserve the existing credential-encryption key and data. Reloading, upgrading and running a workflow are user-run actions; a workflow can send messages, charge money or change external data. Do not execute it as a harmless connectivity test.

## Verify

Use an authorized bounded example and inspect the matching execution result. Test and production webhook endpoints have different activation behavior. A healthy editor does not prove a registered webhook or queue worker works. Keep backups before schema or release changes.

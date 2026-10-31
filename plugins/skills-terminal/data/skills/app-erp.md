Deploy or maintain ERPNext or Odoo with the correct release, database, workers and recovery plan.

## Inspect

Identify the product, edition, release and existing deployment method. Read its manifests and documented compatibility requirements. ERPNext and Odoo do not share a deployment recipe. Do not guess database versions, Python packages, queues or add-on paths.

Inspect service status, bounded application logs, storage, public URL and database connectivity. For a Compose deployment, list services and inspect only the failing component's logs. Check required schedulers/workers and data directories using the chosen release's guide. Filter credentials and business records.

## Propose

Use the product's supported installation and migration workflow as user-run stages. Preview only relevant configuration. Treat application data, attachments, add-ons and database as connected recovery material. Do not repair an installation by running broad dependency upgrades or changing every file owner.

## Verify

Check startup, login, a representative read and required background processing. A database connection alone is not ERP readiness. Before upgrades, establish a recoverable backup and migration sequence. Do not claim restoring old code restores a migrated database. Hand custom application or add-on code changes to CortexCode.

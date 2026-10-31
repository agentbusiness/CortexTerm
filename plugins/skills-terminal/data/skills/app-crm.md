Deploy or maintain Twenty, EspoCRM or SuiteCRM using the selected release's supported procedure.

## Inspect

Identify the actual CRM, release, installation method and target. Read its existing manifests, image tags or package version. Use that release's official self-hosting requirements; the products have different runtimes, databases and worker arrangements. Do not turn one product's recipe into another's.

For Compose, use `docker compose config --services`, `docker compose ps` and bounded logs of the failing service. Inspect only relevant config keys with secret filtering. Establish database, persistent uploads, public URL, mail delivery and any required background jobs. Check capacity before placing the stack beside a local model.

## Propose

Follow installation, configuration, startup and migration as separate user-run stages. Use exact selected versions, existing supported deployment files and a narrow config preview. Keep credentials out of commands and chat. Do not expose the database publicly to fix an application connection.

## Verify

Check login, one non-destructive record read, mail configuration and background-job health. Installation success is not a working CRM. Before an update, save and verify the database plus uploaded data and config; code rollback alone may not reverse a schema migration.

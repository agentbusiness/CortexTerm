Install PostgreSQL or find an existing PostgreSQL server before creating another instance.

## Inspect

Use `command -v psql`, `psql --version`, the service list, and container names. A client binary does not prove a server exists. Establish the target OS, architecture, package manager, available disk, and whether this is development or production. Read the application's required PostgreSQL major version.

## Set up

Prefer the existing managed instance when it meets the request. Otherwise offer one installation method: the target's package manager or its existing container workflow. Use the selected major version; never silently choose a moving latest tag. Installation, cluster initialization, service startup, and role creation are separate changes for the user to run. Never initialize an existing data directory or replace a live volume.

## Verify

Find the actual service, data directory, listener and logs. `pg_isready -h <host> -p <port> -t 5` checks server readiness, not credentials. Follow with a bounded authenticated query of `version()` and `current_database()`. Keep existing data until a backup and restore have been checked.

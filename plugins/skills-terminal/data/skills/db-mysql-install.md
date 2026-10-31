Install MySQL or MariaDB without replacing an existing server or confusing the two products.

## Inspect

Check the target OS, architecture, package manager, containers, service names and `mysql --version` or `mariadb --version`. Establish the requested product and application-supported release. Client output is not proof of the running server version.

## Set up

Offer one installation path matching the target's existing operations. Do not substitute MariaDB for MySQL, or the reverse, without checking application compatibility. Package installation, initialization, account setup and service startup are separate changes. Existing data directories and container volumes are not empty installation targets.

Use the installed release's documented account setup. Do not put an administrator password in a shell command or print generated credentials in diagnostic output. Do not bind a new database to every interface merely to make an application connect.

## Verify

Inspect listener and service logs. Connect using a protected credential method or a user-entered prompt and query `SELECT VERSION(), DATABASE(), CURRENT_USER();`. Confirm the expected product and instance before creating application schemas or importing data.

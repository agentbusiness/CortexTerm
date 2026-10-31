Prepare a Linux host for an application using its actual resources, access and service manager.

## Inspect

Establish the intended host, distribution, architecture, application and release. Check available memory and disk, existing listeners and service manager. Preserve the current administrative connection. Read the release's official supported dependency and installation requirements; do not invent a package list from the product name.

Identify existing reverse proxies, database instances, service accounts, firewall management and backup destinations. Reusing an existing service can be correct; replacing it without checking its dependents is not. An 8 GB host's memory budget must include the OS, model, container VM and application dependencies.

## Propose

Give one user-run preparation step at a time unless a complete runbook was requested. Use supported packages and a dedicated service identity where the product requires it. Do not open database ports publicly or turn off protections to make installation pass.

## Verify

Confirm each dependency's observed version and service readiness before the next stage. Installation, configuration, startup and external access are separate outcomes. Keep the original proxy and service configuration until the new application and recovery procedure have been checked.

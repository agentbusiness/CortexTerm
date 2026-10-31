Deploy or diagnose a Compose stack's service readiness, networks, variables and persistent volumes.

## Inspect

Use `docker compose version`, `docker compose config --services` and `docker compose ps` in the observed project and context. Establish the actual Compose files, profiles and project name. Full rendered configuration and inspect output can expose secrets; select only necessary fields.

Read relevant service definitions. Service-to-service traffic normally uses the service name and container port, not the host-published port. `depends_on` startup order alone does not prove readiness; inspect health checks and retry behavior. Check where relative mounts resolve and whether data lives in persistent volumes.

## Propose

Use a scoped config preview. Validate with the installed Compose tooling, protecting interpolated secrets. Starting, rebuilding and recreating services are user-run changes. Explain affected services. Do not use `down -v`, prune volumes or rename the project as a routine repair.

## Verify

Check health, bounded recent logs and a representative operation across dependencies. A configuration parse or successful `up` is not end-to-end success. Preserve the old image/config and a compatible data backup before upgrades or migrations.

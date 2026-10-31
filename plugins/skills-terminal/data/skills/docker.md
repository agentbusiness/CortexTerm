Inspect Docker or Podman containers, failures, logs, ports and disk use before changes.

## Inspect

Establish engine, context and target. `docker version` and `docker info --format '{{.ServerVersion}}'` can reveal daemon access. A connection failure may involve a stopped service, wrong context, socket or permissions; do not assume Docker Desktop exists on Linux.

Use `docker ps -a --format 'table {{.Names}}	{{.Status}}	{{.Ports}}	{{.Image}}'`. For one failed container: `docker inspect -f '{{.State.ExitCode}} {{.State.Error}} OOM={{.State.OOMKilled}}' <name>` and `docker logs --tail 40 <name>`. Exit 137 means SIGKILL; OOM evidence is needed before naming memory as the cause.

Use `docker stats --no-stream` or `docker system df` when relevant. Never follow logs indefinitely. Do not dump every environment variable or full inspect result: secrets can appear there. Commands inside a container are not automatically read-only.

## Propose and verify

Restart, recreate, rebuild and prune are user-run changes. Explain persistent volumes and stopped-container writable data before cleanup. `--volumes` can remove data. Do not use it as a generic space fix.

After a change, inspect health, recent logs and the original application operation. Running is not readiness. Use the focused Compose or container skill for multi-service setup.

Docker and containers: what runs, logs, ports, a container that exits, disk used by images, compose.

## Look first (with `run`)

- Is the daemon up: `docker info --format '{{.ServerVersion}}'`. "Cannot connect to the Docker daemon": Docker Desktop (or colima, OrbStack) is not running.
- Containers: `docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}\t{{.Image}}'`.
- Why one stopped: `docker inspect -f '{{.State.ExitCode}} {{.State.Error}} OOM={{.State.OOMKilled}}' <name>`, then `docker logs --tail 50 <name>`. Exit 137 with OOM=true: it ran out of memory.
- Never `docker logs -f` or `docker compose logs -f`: they never end. Use `--tail 50` or `--since 10m`.
- Resource use: `docker stats --no-stream`.
- Disk: `docker system df`.
- Compose: `docker compose ps` and `docker compose config --services` in the project folder.
- Inside a container (read only): `docker exec <name> cat /etc/os-release`, `docker exec <name> env`.

## Common causes

- "port is already allocated": another container or program holds it (`docker ps --format '{{.Names}} {{.Ports}}'`, `lsof -nP -iTCP:<port> -sTCP:LISTEN`).
- A container that restarts over and over: read the first error in `docker logs --tail 100`.
- localhost inside a container is the container itself. The Mac from inside: `host.docker.internal`.
- A volume mount that looks empty: the path is relative to where compose runs, or Docker Desktop has no access to that folder.

## Changes (theirs to run)

- Restart one: `docker restart <name>`. Rebuild with compose: `docker compose up -d --build`.
- Free space: `docker system prune` removes stopped containers, unused networks and dangling images. Add `-a` only if they agree to lose every unused image (they download again). `--volumes` deletes data: say so plainly.

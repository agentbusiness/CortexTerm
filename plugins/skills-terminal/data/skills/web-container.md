Build or run a container with the intended image, ports, mounts and resource limits.

## Inspect

Identify Docker or Podman, daemon context, target architecture and existing project container files. Use bounded version, image and container metadata. Inspect Dockerfile and ignore rules before a build. Do not dump all environment values or registry credentials.

Establish the persistent data path, container user, network, port exposure and memory needs. Container localhost is the container itself. A writable layer is not a durable backup. Image architecture must match the target or a deliberately supported emulation path.

## Propose

Building, pulling and starting are user-run actions. Use an explicitly chosen supported image version or digest; do not silently follow `latest`. Bind only intended interfaces and preserve named volumes. Do not grant privileged mode or mount the daemon socket as a generic fix.

## Verify

Inspect startup logs, exit status, health and a real application operation. A running container does not prove readiness. Keep the prior image and data recovery path for updates. Do not remove volumes while cleaning old containers.

Set up or diagnose HAProxy frontends, backends, health checks, TLS and timeouts.

## Inspect

Use `haproxy -vv` and the service's actual command to locate all configuration files and their order. Inspect the relevant frontend, defaults and backend. Check bind address, mode, backend selection, health-check method, TLS settings and timeouts. Do not assume every failed backend means a network failure; the health check may use the wrong path or hostname.

Compare backend reachability from the HAProxy host or network. Read bounded service and application logs. Runtime changes may differ from persistent files; establish which configuration the running process uses.

## Propose

Use a scoped config preview. Validate all intended files with the installed binary's `-c -f <file>` check mode, preserving their order. A successful syntax check does not establish backend health. Reload through the existing service's supported method as a user-run action.

## Verify

Inspect backend health and the original request path after reload. Confirm sessions and protocol behavior relevant to the service. Keep the previous files and release for recovery; do not replace the load-balancing policy or restart every backend to clear one error.

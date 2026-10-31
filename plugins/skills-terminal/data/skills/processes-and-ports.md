Find a slow process or port owner and choose a scoped stop only when necessary.

## Inspect

Use current metrics first. On macOS: `ps -axo pid,ppid,%cpu,%mem,rss,etime,comm -r | head -15`; on a compatible GNU ps use its supported sorting options. Check the actual tool on minimal Linux systems.

For a port: `lsof -nP -iTCP:<port> -sTCP:LISTEN` or a relevant Linux ss query. For an observed PID: `ps -o pid,ppid,etime,command -p <pid>`. Avoid exposing credential arguments. Explain the owning application and service before calling its process a problem.

## Propose

Recheck identity immediately before a stop; PIDs can be reused. The person may send SIGTERM first so the process can clean up. SIGKILL is a later explicit action that can lose work. A supervised service may restart: use its service manager rather than repeatedly killing children.

## Interpret and verify

Exit 127 suggests command resolution failed. Exit 126 can involve executable permissions, format or interpreter problems; inspect the actual error before suggesting chmod. Exit 137 indicates SIGKILL, not its cause. Check memory evidence before naming OOM.

After a stop or repair, inspect the intended process or port and repeat the affected operation. Do not claim success from disappearance alone.

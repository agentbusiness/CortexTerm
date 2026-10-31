Inspect or manage a Linux systemd service, its unit, drop-ins and startup failure.

## Inspect

Confirm the target uses systemd and identify the exact unit. Use `systemctl status <unit> --no-pager`, `systemctl cat <unit>` and `journalctl -u <unit> -n 40 --no-pager`. Read environment paths and relevant settings without dumping secrets. User services need the corresponding `--user` commands.

Inspect the executable, service user, working directory, dependencies and effective drop-ins. A killed child may restart because its supervisor is working correctly. `active` is a process state, not proof the application is ready or reachable.

## Propose

Use a config preview for a scoped unit or drop-in change. Validate with the installed systemd tooling. Reloading unit definitions, starting, stopping, enabling or restarting are separate user-run changes; explain which is required. Do not restart every service to repair one.

## Verify

After the action, inspect unit state, recent logs and the intended endpoint or operation. Keep previous unit text for recovery. If a restart loops, read its first relevant error before changing restart policy or permissions.

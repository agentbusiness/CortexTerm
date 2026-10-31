Edit systemd units or drop-ins and check the effective service configuration.

On the Linux target, inspect `systemctl cat <unit>` and bounded `systemctl show` fields. Read unit sources and drop-ins. Confirm whether a package owns the main unit.

Prefer a scoped drop-in for a packaged service. Inspect the actual file with format `systemd`. A directive can append, replace or require an empty reset depending on its type. Do not append another `ExecStart` without checking its rules.

Use a unique preview and inspect hash for non-secret changes. Administrator-owned files need the editor's privileged save workflow. Environment values and command arguments can contain credentials; do not print them wholesale.

The helper does not understand systemd semantics. Offer `systemd-analyze verify <unit-file>` when available, using the actual target version. After the person saves, offer daemon reload if the unit changed, then the required service restart.

Check the effective unit, process state and bounded journal output. A parsed unit is not proof the program started correctly. Keep the original drop-in and service access available for recovery.

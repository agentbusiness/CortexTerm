Diagnose permission denied, ownership, ACLs and protected folders before changing access.

## Inspect

Read the exact failing path and operation. Use `id` and `ls -ld '<path>' '<parent>'`; on macOS `ls -ldeO@` also shows ACLs, flags and attributes. On Linux, use `namei -l '<path>'` or `getfacl` when installed. Access depends on parent directories too.

Distinguish permission bits, ownership, ACLs, read-only mounts and macOS privacy controls. `Operation not permitted` on protected Mac data can require an operating-system privacy grant; `sudo` does not bypass every restriction.

## Propose

Change only the required object and permission. Explain the intended owner or group before using `chown`. Never default to `chmod -R 777`, recursive ownership of a project tree, or disabling a protection. A secret file may need less access, not more.

## Verify

After the person runs the change, inspect permissions again and repeat the original operation. Report whether that operation works. If access still fails, inspect the next relevant cause; do not keep widening access. Preserve original metadata when a rollback may be needed.

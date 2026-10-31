Edit SSH client or server configuration while preserving rule order and remote access.

First distinguish client `ssh_config` from server `sshd_config`. Find the actual file and included files on the target. Inspect with format `ssh`.

For clients, `Host` and `Match` scope and first-obtained values matter. Inspect effective settings with `ssh -G <host>` using bounded selected fields. Avoid revealing proxy credentials or private-key contents.

For servers, keep the current remote session open and retain console or another recovery path. Preview one unique block with the inspect hash. Administrator-owned files use the editor. Do not weaken authentication to make a connection work.

Offer the installed server's `sshd -t` with its actual config path and permissions. For `Match` rules, an effective-config check may need connection criteria; use that version's help. Client and server validation are different.

Only after successful checks should the person reload the SSH service. Verify a second independent connection before closing the original session. A changed host fingerprint must be checked through a trusted channel, not removed merely to silence the warning.

Identify the target machine's operating system, distribution, architecture and available tools.

## Inspect

Use the selected target's facts. For macOS: `sw_vers`, `uname -m`, and `sysctl -n hw.memsize`. For Linux: `uname -srm` and a bounded read of `/etc/os-release`. A container's distribution and utilities can differ from its host.

Check required tools with `command -v`. Inspect a tool's version or help before assuming GNU, BSD or BusyBox options. Linux does not imply that every GNU flag exists. Apple silicon can run translated Intel binaries; distinguish the machine architecture from a particular process.

## Interpret

Report the facts needed for this task: platform, architecture, relevant version and available tool. Do not print unrelated serial numbers or identifiers. A local workstation's facts do not describe an SSH destination.

Before proposing an installation or configuration, identify the package manager, service manager and intended target. If the target is ambiguous, ask one precise question. Never apply local macOS instructions to a Linux server merely because the assistant runs on the Mac.

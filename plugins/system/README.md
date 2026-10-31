# System monitoring

Linux runner monitoring in **0.1.15** retains CPU, RAM/swap/pressure, load, root filesystem space, disk I/O, network throughput, processes, ports, signals, schedules and traces. Open files, pipes and socket endpoints come directly from procfs, with no lsof dependency. Thread CPU uses successive readings. The network watcher checks destinations and connection patterns on Linux; route/resolver inspection no longer invokes Mac utilities.

Readable hwmon/thermal, DRM, power-supply and RAPL data supply optional temperatures, fans, GPU use, battery and package power. Missing hardware/permissions leave these readings unavailable. Per-connection byte totals, per-process GPU timing and macOS-only security facilities are not invented. Full support boundaries and verification status: [RUNNER.md](../../RUNNER.md).

Security findings in **0.1.18** carry a group, decisions (`system.finding.decide`) replace the
per-finding ignore, a fix can be checked again (`system.finding.verify`), the chart reads
`system.security.history`, `macsec weakness` answers by kind of flaw, and the malware scan skips
both XProtect bundles. See [docs/PROTECTION.md](../../docs/PROTECTION.md).

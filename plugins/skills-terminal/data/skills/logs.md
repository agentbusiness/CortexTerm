Find why something failed in logs: macOS unified log, app and crash logs, system journal, log files.

`run` shows only about 60 lines: always filter and limit. Never follow a log (`tail -f`, `log stream`, `journalctl -f`): it never ends.

## macOS

- The unified log, filtered and recent: `log show --last 10m --style compact --predicate 'process == "<name>"' | tail -40`. Errors only: add `and messageType == error`. By text: `--predicate 'eventMessage CONTAINS[c] "<text>"'`. Keep `--last` short: a long window is slow.
- Crash reports: `ls -t ~/Library/Logs/DiagnosticReports | head`. Read the top of the newest: the exception type and the first frames of the crashed thread say most.
- App logs: `~/Library/Logs/<app>/`, Homebrew services: `$(brew --prefix)/var/log/`.
- Why the Mac slept, woke or restarted: `pmset -g log | grep -E 'Sleep|Wake|Shutdown' | tail -20`.

## Linux

- A service: `journalctl -u <unit> -n 50 --no-pager`. Since a time: `--since "1 hour ago"`. Errors: `-p err`.
- This boot's errors: `journalctl -b -p err -n 50 --no-pager`. The previous boot: `-b -1`.
- Kernel (OOM kills, disks): `dmesg -T | tail -30` (may need sudo).
- Files: `/var/log/syslog` or `/var/log/messages`.

## Any log file

- The end: `tail -n 50 <file>`.
- Errors with context: `grep -n -i -E 'error|fail|fatal|panic' <file> | tail -20`, then `sed -n '<from>,<to>p' <file>` around a hit.
- Count by kind: `grep -o -E 'ERROR [A-Za-z]+' <file> | sort | uniq -c | sort -rn | head`.
- Compressed: `zgrep`, `zcat <file>.gz | tail`.

Quote the one line that explains the failure, with its time, and say what it means. The first error is usually the cause; later ones follow from it.

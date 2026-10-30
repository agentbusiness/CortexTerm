A process is slow, stuck, using too much CPU or memory, or holds a port; something must be stopped.

## Look first (with `run`)

- Busiest by CPU: `ps -axo pid,ppid,%cpu,%mem,rss,etime,comm -r | head -15` (macOS; `ps aux --sort=-%cpu | head` on Linux).
- Busiest by memory: `ps -axo pid,rss,%mem,comm -m | head -15` (macOS; `--sort=-rss` on Linux). `rss` is in KB: divide by 1024 for MB.
- One program by name: `pgrep -lf <name>`. Its full command line: `ps -o pid,etime,command -p <pid>`.
- Who holds a port: `lsof -nP -iTCP:<port> -sTCP:LISTEN`. Every listening port: `lsof -nP -iTCP -sTCP:LISTEN`.
- What a process has open: `lsof -p <pid> | head -40`.
- Its children: `pgrep -P <pid> -l`.

Say what the process is (the app or tool it belongs to) before saying it is a problem. A busy `mds_stores`, `kernel_task` or `WindowServer` is macOS doing its work, not something to stop.

## Stopping one (theirs to run, in a ```sh block)

1. Ask it to quit: `kill <pid>` (SIGTERM). It can save and clean up.
2. Only if it is still there after a few seconds: `kill -9 <pid>`. Say that unsaved work in it is lost.
3. By name: `pkill -x <name>`. Show `pgrep -lx <name>` first so they see what it matches.
4. A process of another user or root needs `sudo`.

A service started by launchd or systemd comes back after a kill: stop the service instead (`brew services stop <name>`, `launchctl bootout gui/$(id -u)/<label>`, `sudo systemctl stop <unit>`).

## Exit codes in a failed Run

| Exit | Meaning |
|---|---|
| 1, 2 | failure, usage error (grep: 1 = no match) |
| 126 | not executable: `chmod +x`, or a CRLF line ending in the script |
| 127 | command not found: not installed or not on PATH (`command -v <name>`) |
| 130 | stopped with Ctrl-C |
| 137 | killed: out of memory, or `kill -9` |
| 141 | the reader (`head`) stopped early: usually harmless |

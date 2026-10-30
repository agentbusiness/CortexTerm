# cortexterm

```sh
npx cortexterm
```

Starts [CortexTerm](https://github.com/agentbusiness/CortexTerm), an AI terminal with a local model. The first
run downloads the app for this machine (Apple Silicon Macs; Linux x64 and arm64) from the official
releases, checks it against the checksum in the release catalog and unpacks it into `~/.cortexterm/app/`.
Later runs start the installed app at once; the app updates its frame and plugins itself. The app
runs on its own: you can close the terminal (its start output goes to `~/.cortexterm/logs/start.log`);
running the command again while it runs only says so.

Arguments go to the app: `npx cortexterm --headless`, `npx cortexterm --safe`.

## Background runner (macOS and Linux)

```sh
npx cortexterm runner
npx cortexterm runner join <invitation>
```

The runner keeps terminal execution, metrics, monitoring, memory, mesh and updates running in the background. It never downloads or loads a local chat model; AI uses an available model in the mesh. Shell commands execute on this machine and work without AI.

On macOS it installs a LaunchAgent that starts at login. On Linux it installs a systemd service and enables user linger so it starts at boot and survives SSH logout (the installer explains when an administrator must enable linger). The service starts the installed frame directly, independently of npx's cache. Updates requiring a core restart are applied automatically after active work settles. Existing PTY shells survive restarts.

`npx cortexterm runner off` stops the service. macOS output is in `~/.cortexterm/logs/runner.log`; Linux uses `journalctl --user -u cortexterm-runner.service` (without `--user` for a root-installed service). On non-systemd Linux, use `npx cortexterm --runner --foreground` under your supervisor.

Development uses `./cortexterm runner` from the checkout; `./cortexterm --build-only` refreshes the build and the runner automatically restarts when the core changed. Development stays on local builds. Full details: [runner documentation](https://github.com/agentbusiness/CortexTerm/blob/main/RUNNER.md).

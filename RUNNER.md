# Background runner

Implemented for frame **0.1.12**, updater **0.1.15**, system **0.1.15**, terminal **0.2.3** and npm launcher **0.1.2**. These source changes require a subsequent build/release before published `npx cortexterm` can use them.

The runner executes shells and commands **on the machine where it runs**. It keeps that machine's metrics, process monitoring, schedules, memory, mesh connection and updater active without a graphical window. It never starts a local chat-model backend: no Gemma/Qwen download, load or CPU/GPU inference. Its terminal chat flow still claims any suitable `coding` or `office` model in the mesh, and session model calls use that remote route. Ordinary shell commands do not need a model or a mesh connection.

This is a CortexTerm launch profile, not a change to the plugin package, mesh protocol, shared model contracts or shared services. Desktop model preferences are not rewritten. IronGraph memory retains its existing embedded search/embedding engine; disabling the local chat model does not disable local memory.

## Released app

```sh
npx cortexterm runner
npx cortexterm runner join <invitation>
```

The installer starts the installed frame directly through the operating system's service manager. The service does not depend on npx's temporary cache or on a shell window remaining open. There is one managed runner per OS account. A second CortexTerm sharing the same `CORTEX_HOME` is refused; stop it before installing the runner.

On macOS, the service is `~/Library/LaunchAgents/com.cortexterm.runner.plist`: it starts at login and restarts on exit. It is a per-user login service, not a boot daemon running before login.

On Linux with systemd, a normal user gets `~/.config/systemd/user/cortexterm-runner.service` (or `$XDG_CONFIG_HOME/systemd/user/`). The installer enables that user's linger setting so the service starts at boot and survives SSH logout. If the account cannot enable linger, the installer reports the administrator command instead of claiming persistence succeeded. Running the installer as root creates `/etc/systemd/system/cortexterm-runner.service` with root's own CortexTerm home. A Linux host without systemd can run `npx cortexterm --runner --foreground` under its existing supervisor; automatic service installation requires systemd.

Linux output is in the service journal (`journalctl --user -u cortexterm-runner.service`, or omit `--user` for the system service). macOS service output is in `~/.cortexterm/logs/runner.log`. Both platforms also have the frame and plugin logs under `<CORTEX_HOME>/logs/`.

```sh
npx cortexterm runner off
```

This stops and disables the service. It preserves the home, memory and existing `cortexd` terminal shells. Linux's service uses `KillMode=process`: the frame owns cleanup of its recorded plugin children, while the separate terminal daemon and its shells survive service restarts. Explicitly stopping the service suppresses its automatic restart. The installer does not remove a user's linger setting on stop, since other user services may use it.

## Development

```sh
./cortexterm runner
```

The same installer brings the development build up to date, then points the service at this checkout's built frame. Linux development builds use `build/cortexterm/`; macOS uses `build/CortexTerm.app/`. The service carries `CORTEXTERM_DEV_ROOT` and `CORTEX_NO_HANDOVER=1`, so restarting never replaces the checkout with a staged release. Startup at boot/login does not compile the repository.

To refresh a running development runner after editing source:

```sh
./cortexterm --build-only
```

The build places a new restart marker only after a complete successful build, and only when the frame, its config, Electron or its shell changed. The updater checks that marker every five seconds and restarts onto the completed local build when work has settled. Subsequent build-only refreshes use the live build path, so changed plugins hot-swap into the running frame; packages are also adopted at startup. Released packages never overwrite a development runner's plugins. Stop with `./cortexterm runner off`.

## Updates and restarts

The updater remains enabled in runner mode even when the desktop's updater was disabled; its saved preference stays intact. Released runners check the catalog 30 seconds after startup and every hour by default. Plugin releases install through the normal package updater; a required frame release is downloaded, verified and staged. Every five seconds the runner checks whether a staged core update can restart automatically. Development uses the local build marker instead of installing releases.

Restart checks defer during another update operation, active chat-flow runs, background terminal command-service jobs, due scheduled work, and in-flight system/terminal service calls. Unreadable activity checks defer the restart. Persistent PTY shells remain in `cortexd` across the restart; plugin-owned work is allowed to settle first. The old frame is not replaced by an incomplete or failed download. A shell attached to a runner may close its UI without shutting down the runner.

## Linux monitoring

The Linux runner retains the ordinary terminal and system plugins. CPU/core usage, RAM, swap, memory pressure, load, disk space, physical-device I/O, network throughput, processes, per-process CPU/memory/I/O, listening TCP ports, process signals, schedules and process traces use Linux sources. Root filesystem space uses `statvfs`, including overlay filesystems. Listening ports remain visible with an unknown owner when descriptor permissions prevent attribution.

Open files, pipes and socket endpoints are read directly from `/proc`; `lsof` is not required. Thread CPU is measured between reads. The network watcher uses Linux socket tables and continues destination/threat-list and connection-pattern monitoring. Default routes, resolver addresses, router neighbours and public IPv6 addresses use procfs and resolver configuration rather than macOS commands.

Temperatures, fans, battery, GPU utilisation and package power are optional: they appear only when the kernel/driver exposes readable hwmon, thermal, DRM, power-supply or RAPL counters. A server with no GPU or battery reports those fields as unavailable. Procfs does not supply per-connection byte totals: upload-volume detection is explicitly marked unavailable, while aggregate network throughput still works. Per-process GPU time and macOS security facilities (TCC, Gatekeeper, SIP, XProtect and launchd inspection) have no fabricated Linux readings; existing Mac-specific checks report that they are unavailable. Access to another user's descriptors and logs remains limited by the server's permissions.

## Verification for this change

The user requested **no build**. JavaScript and shell syntax, Rust source parsing, generated macOS/Linux user/root/development service definitions, escaping, manifest consistency and the final source diff were reviewed without compiling or installing a service. New binary behavior, Linux service startup, metrics readings and live mesh inference still need verification on real machines after an authorized build.

Platform references: [systemd service restart behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html), [systemd process cleanup](https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html), [loginctl linger](https://www.freedesktop.org/software/systemd/man/latest/loginctl.html), [Linux hardware sensor files](https://docs.kernel.org/hwmon/sysfs-interface.html).

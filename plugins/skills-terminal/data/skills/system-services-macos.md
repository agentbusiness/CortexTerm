Inspect or manage macOS launchd agents, daemons and Homebrew services.

## Inspect

Establish whether the job belongs to the user GUI domain, a user domain or the system. Use `brew services list` when Homebrew manages it. For an observed label, `launchctl print <domain/label>` shows state and the last exit result. Read the actual plist with bounded `plutil -p` output, filtering secret values.

Distinguish a login agent from a system daemon. Check program arguments, working directory, logs, user and keep-alive settings. A process returning after a kill may be relaunched by its job. Do not assume a plist filename equals its Label.

## Propose

Validate plist syntax before a user-run load or replacement. Use the manager that owns the service; do not manage the same job independently through Homebrew and manual launchctl commands. Explain whether it starts now, at login or at boot.

## Verify

Inspect the same domain and label, its logs, and the application's behavior after the action. Loaded or running does not establish readiness. Keep the old plist or service settings for recovery, and avoid unrelated login items.

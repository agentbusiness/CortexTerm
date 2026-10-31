Set up or diagnose cron jobs, systemd timers or macOS launchd schedules.

## Inspect

Identify the target OS, user and existing scheduler. Read a known job: `crontab -l`, `systemctl list-timers --all --no-pager`, or `launchctl print <observed-domain/label>`. Limit output and filter credentials. A job may run under a different user, PATH, directory and time zone than the interactive shell.

Read the command or script before changing its schedule. Check absolute executable paths, working directory, permissions, logs and overlap behavior. Cron syntax and launchd calendar rules are not interchangeable.

## Propose

Preview the exact entry or unit change. Explain time zone, frequency and what happens if the machine is asleep or a previous job is still running. Use the existing scheduler; do not create a second schedule for the same task. Enabling or loading a job is a user-run change.

## Verify

Inspect the next scheduled time and the next actual execution result. A valid schedule does not prove its command works. Keep the previous entry for recovery and distinguish a manual successful run from a successful scheduled run.

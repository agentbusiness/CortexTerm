Run a web application under its existing process manager or operating-system service manager.

## Inspect

Identify the application release, documented start command, service manager, user, working directory, environment source and intended port. Read declared dependencies and startup logs. Do not guess a development-server command for production. Avoid printing secret environment values.

Check file and data ownership, persistence, health endpoint and shutdown behavior. A process that exists may still be waiting for a database or migration. A supervisor restart loop usually needs the original application error, not a more aggressive restart policy.

## Propose

Use a config preview for the relevant service definition. Validate syntax and required paths. Starting, enabling, reloading and restarting are different user-run operations; explain the chosen one. Keep database migrations as a separate explicit step with recovery implications.

## Verify

Inspect manager state, bounded recent logs, the listening address and a representative application request. Confirm startup after the intended lifecycle event when required. Preserve the old release and settings until the new service works. Hand application-code changes to CortexCode on the repository's machine.

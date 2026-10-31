Identify macOS tools, Homebrew installations, launchd jobs and operating-system access limits.

## Inspect

Use `sw_vers`, `uname -m` and task-relevant current facts. `command -v <tool>` and supported `type -a <tool>` show what actually runs. Homebrew's prefix is discovered with `brew --prefix`, not assumed from the CPU name. System utilities and installed GNU tools can have different flags.

Typical BSD forms include `sed -i ''`, `stat -f` and `du -d`; verify the selected utility before using them. macOS has no standard GNU `timeout` or Linux `free`. Inspect the relevant `launchctl print <domain/label>` or Homebrew service when a background job fails.

## Propose

Use a config preview for a setting or file change and preserve its previous value. Do not disable SIP or Gatekeeper as a repair. For a blocked downloaded app, establish its official source and signature/notarization status before considering any override; quarantine removal bypasses a check.

Protected-folder access can require a specific privacy grant. Grant only the access the task requires; `sudo` does not bypass every macOS privacy rule.

## Verify

Repeat the original operation and inspect actual state. A settings command exiting zero is not proof the application reloaded the value.

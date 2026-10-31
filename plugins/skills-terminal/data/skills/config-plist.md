Edit Apple plist configuration while preserving types and validating launchd settings.

Use `file <path>` or the editor to identify XML versus binary plist. Do not treat a binary plist as UTF-8 text. The config helper supports text XML plists; use the native editor or `plutil` workflow for binary conversion.

Inspect with format `plist`. Preserve value types: `<true/>`, `<integer>` and `<string>` are different. Read paired dictionary keys and values, complete arrays and the relevant launchd domain.

Preview one unique non-secret block with the inspect hash. Keep XML escaping. Standard plist declarations are supported; custom entity declarations are refused. Do not add shell syntax to a `ProgramArguments` array: launchd does not interpret it as a shell command.

Offer `plutil -lint <path>` on the actual target. Parsing does not establish that launchd accepts the job's semantics or permissions.

After user apply, use the correct user/system launchd lifecycle procedure. Check the job's state and bounded logs. Keep the original plist and the current terminal session available for recovery.

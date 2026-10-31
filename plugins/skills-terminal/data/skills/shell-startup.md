Edit shell startup files, aliases or prompt settings without duplicate or conflicting entries.

## Inspect

Identify the actual shell and whether the session is login or interactive. Inspect only the relevant startup sections with `config` or bounded file reads. For zsh, `.zshenv`, `.zprofile` and `.zshrc` serve different purposes; Bash has different startup rules. Respect an observed custom configuration directory.

Find existing definitions before adding one. Trace files that source other files. An environment value may come from a runtime manager or operating-system service rather than the file being viewed.

## Propose

Use `config` preview for one exact change. Show the file, section and effect. Do not repeatedly append exports or aliases. Avoid replacing a whole startup file. Prefer a syntax check in the actual shell; syntax validity alone does not prove commands inside are harmless.

## Verify

The person opens a fresh matching shell and checks the intended value or alias. Do not source an unfamiliar startup file automatically: sourcing executes its contents. Keep the previous text for recovery if the new shell fails to start correctly.

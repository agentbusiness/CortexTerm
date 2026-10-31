Find why a command is missing or why the wrong executable or version runs.

## Inspect

Use `command -v '<name>'` and, when supported, `type -a '<name>'` or `which -a '<name>'`. Inspect the selected binary's version with its documented flag. An alias or shell function can take precedence over a file on PATH.

Print PATH alone, not the entire environment: `printenv PATH`. Compare login-shell, application, service and virtual-environment context. A change in one terminal does not necessarily affect a GUI app or system service. On Apple silicon, also inspect architecture before blaming versions.

## Propose

Choose one intended installation or runtime manager. Add or reorder only the needed PATH entry in the correct startup file using a config preview. Do not delete other installations merely because several exist. Do not append the same export on every retry.

## Verify

Start the appropriate fresh shell or reload only the relevant configuration, then check resolution and version again. Shell command caches may need their documented refresh. Report the actual executable path now used, not merely that an installation command exited zero.

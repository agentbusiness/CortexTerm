Handle a command that needs a keyboard, password, confirmation, editor, pager or REPL.

`run` has no keyboard and stops after 20 seconds. It can inspect; it cannot conduct an interactive session.

## Inspect without interaction

Use bounded commands such as `git --no-pager log -10`, `systemctl status <unit> --no-pager`, or `man <command> | col -b | head -40`. Do not launch `vim`, `nano`, a bare REPL, `sudo` or a password-based SSH session through `run`. A noninteractive flag must match the installed program.

Do not pipe guessed answers into an installer. Do not add a yes flag just to prevent a prompt; it may accept removal, replacement or other consequential choices. A shell wrapper does not turn a refused operation into an allowed read.

## Propose

Give the person the command and explain the actual question they will encounter. Password input may show no characters. Keep passwords out of chat and shell arguments.

For file changes, inspect the current file and use `config` preview. It shows a scoped change; applying remains the person's action. Do not repeatedly append lines or use broad substitutions across structured configuration.

## Verify

Continue from the person's recorded result. A command awaiting input has not completed, and no output does not prove success.

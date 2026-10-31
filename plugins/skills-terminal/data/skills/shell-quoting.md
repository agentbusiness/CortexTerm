Explain shell quotes, spaces, wildcards, variables and command substitution.

## Inspect

Use the selected shell's facts; Bash, zsh and POSIX sh differ. Read the literal command as entered. Single quotes preserve their contents. Double quotes allow variable and command substitution. Unquoted expansions can split words or expand wildcards according to the shell's rules.

To show argument boundaries, use a harmless `printf` example with known literal values. Do not evaluate an unfamiliar command just to discover its expansion. `$(...)`, backticks, redirections and process substitutions can execute or write before the apparent command runs.

## Correct

Quote each variable or literal path that must be one argument. Use an option terminator where supported when a filename starts with `-`. Do not use `eval` to fix quoting. In zsh, an unmatched glob may fail before the program starts; the same text can behave differently in another shell.

Give the corrected command as a user-run proposal if it changes anything. Explain the one expansion that caused the problem. Verify the intended argument or resulting path without rerunning a destructive command.

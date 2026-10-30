A program asks questions or waits for keys: installers, prompts, sudo, REPLs, editors, pagers, `ssh` passwords.

`run` has no keyboard: such a program gets nothing and hangs until it is stopped. So:

## Reading without a prompt (with `run`)

- Pagers: `git --no-pager log -20`, `man <cmd> | col -b | head -60`, `PAGER=cat`, `systemctl --no-pager`.
- No questions: `brew info`, `apt-cache policy`, `npm view <pkg> version` read without asking.
- Never `sudo` in `run`: it asks for a password. Say what you would look at with sudo and give it to them.
- Never an editor (`vim`, `nano`) or a REPL (`python`, `node`) in `run`. For a value: `python3 -c '...'`, `node -e '...'`.

## Commands for them that will ask

When the command you give asks something, say what it will ask and what to answer:

- `sudo`: their login password, typed blind (nothing shows).
- An installer: the answers it will ask for, or the flag that skips them: `-y` (apt, conda), `--yes`, `--non-interactive`, `HOMEBREW_NO_AUTO_UPDATE=1`, `npm init -y`.
- `ssh-keygen`: where to save (Enter keeps the default) and a passphrase.
- Known answers piped in: `printf 'y\n\n' | ./install.sh` (an empty line takes the default). Only when they know the questions.

## Editing a file

They run the change, not an editor you open. Prefer a command that shows exactly what changes:
- Add a line: `echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.zshrc`, then `source ~/.zshrc`.
- Replace on macOS: `sed -i '' 's/old/new/' <file>` (Linux: `sed -i`). Keep a copy first for anything important: `cp <file> <file>.bak`.
- Or `nano <file>` when they prefer to edit by hand: say which line to change.

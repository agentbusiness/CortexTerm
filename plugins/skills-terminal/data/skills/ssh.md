SSH: keys, connecting to a server, config, agent, GitHub access, "permission denied", host key warnings.

## Look first (with `run`)

- Keys: `ls -l ~/.ssh`. A key is a pair: `id_ed25519` (private, never shared) and `id_ed25519.pub` (public, goes to the server or GitHub).
- Config: `cat ~/.ssh/config`. What ssh will use for a host: `ssh -G <host> | grep -E '^(hostname|user|port|identityfile) '`.
- Keys in the agent: `ssh-add -l`.
- GitHub: `ssh -T -o BatchMode=yes git@github.com` answers "Hi <user>!" when the key works (it exits 1 even then).

`run` has no keyboard: an ssh command that asks for a password or a yes/no hangs. Add `-o BatchMode=yes -o ConnectTimeout=5` to every ssh you run yourself.

## Debugging a connection

`ssh -v -o BatchMode=yes -o ConnectTimeout=5 <host> true 2>&1 | grep -E 'Offering|Authenticated|denied|Connection|identity file'` shows which keys were tried and why it failed.

- `Permission denied (publickey)`: the server does not have this public key, or ssh offered another one. Fix with `IdentityFile` in the config.
- `Connection refused` or a timeout: wrong host or port, no ssh server, or a firewall (see the networking skill).
- `REMOTE HOST IDENTIFICATION HAS CHANGED`: the server's key changed. If they expected it (reinstall), `ssh-keygen -R <host>`. If not, stop: it can be an attack.
- `UNPROTECTED PRIVATE KEY FILE`: `chmod 600 ~/.ssh/id_ed25519; chmod 700 ~/.ssh`.

## Setting up (theirs to run, one step per answer)

1. New key: `ssh-keygen -t ed25519 -C "<their email>"` (it asks for a passphrase: recommend one).
2. macOS keychain: in `~/.ssh/config`:
   ```
   Host *
     AddKeysToAgent yes
     UseKeychain yes
     IdentityFile ~/.ssh/id_ed25519
   ```
   then `ssh-add --apple-use-keychain ~/.ssh/id_ed25519`.
3. To a server: `ssh-copy-id -i ~/.ssh/id_ed25519.pub <user>@<host>`. To GitHub: `pbcopy < ~/.ssh/id_ed25519.pub`, then paste it at github.com/settings/keys.
4. A short name: a `Host <alias>` block with `HostName`, `User`, `Port`.

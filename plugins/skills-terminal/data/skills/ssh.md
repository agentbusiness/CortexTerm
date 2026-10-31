Set up or diagnose SSH keys, agent selection, authentication and host identity.

## Inspect

Use `ls -l ~/.ssh` without reading private key contents. `ssh-add -l` lists agent identities. For an observed host, inspect `ssh -G <host>` filtered to hostname, user, port and identityfile. Do not dump unrelated config or credentials.

A network probe needs `-o BatchMode=yes -o ConnectTimeout=5` and a known bounded remote command; `run` may require it to be offered to the person. Never wait for a password prompt or disable host-key checking to make a probe proceed.

## Interpret

`Permission denied (publickey)` can involve user, offered identity, agent, server permissions or server policy. Read actual authentication evidence before selecting a cause. A timeout and a refusal point to different network/service states.

A changed host key needs a fingerprint verified through a trusted independent route, even after an expected reinstall. Only then offer a scoped known_hosts update. Never remove the whole file.

## Propose and verify

Key generation, agent changes and public-key installation are user-run actions. Preserve existing keys; private keys never leave the machine. Use the installed platform's keychain options. Confirm authentication to the intended host and user afterward. A Git hosting SSH probe can report successful authentication with a nonzero exit; interpret its actual message.

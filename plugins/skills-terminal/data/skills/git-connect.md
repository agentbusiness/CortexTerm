Clone a Git repository or diagnose its SSH or HTTPS authentication.

## Inspect

Confirm the intended repository and destination. `git --version`, `git rev-parse --show-toplevel` and `git remote` establish local context without dumping credential-bearing URLs. Inspect the chosen remote carefully and mask embedded credentials before output. Never read a credential store or private SSH key into the model.

For SSH, use `ssh -G <observed-host>` with a filter for hostname, user, port and identityfile. A remote authentication probe is network activity and may need a user-run proposal. Use batch mode and a connection timeout; do not wait for hidden prompts.

## Propose

Give the exact official clone URL and a nonconflicting destination. Do not place access tokens in command arguments or URLs. Use the user's existing credential manager or SSH agent. For changed host keys, verify the fingerprint through a trusted route before replacing records.

## Verify

After cloning, inspect the repository root, branch and file presence. A clone does not establish dependencies or build readiness. Diagnose errors from the actual transport result; do not switch authentication methods or disable TLS verification blindly.

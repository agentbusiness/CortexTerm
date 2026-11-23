SSH needs a look: folder or key permissions, a weak or passphrase-less key, or an authorized_keys entry.

Means: SSH keys open servers and git hosts.
authorized_keys decides who may log in to this Mac.

Normal when:
- no passphrase, and `what` says an agent holds the key (Secretive, 1Password) or it is ed25519.
- authorized_keys, seen_days 30 or more, count 1 (a key for the person's other computer).
- permissions, path_class home_hidden, a key a local VM tool made (Docker, Colima, Lima).

Suspicious when:
- authorized_keys changed, seen_days 0, parent not terminal (backdoors and worms add their own key).
- a private key readable by group or others, or a copy in temp, downloads or shared.
- a weak key (DSA, or RSA under 2048 bits) with no passphrase.

Never decide from: the key comment (user@host) or file names in `what`.
Precedent: a match with the same rule supports the same verdict only if nothing changed since, never over a suspicious fact.
When unsure: escalate.

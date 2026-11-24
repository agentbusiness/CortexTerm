SSH needs a look: loose permissions, a weak key, or an authorized_keys entry.

Questions:
- held_safely: is the key held safely? Yes when what says an agent holds it (Secretive, 1Password, the keychain).
- tool_key: did a local VM tool make it? Yes when what names Docker, Colima or Lima.
- new_login_key: was a login key added lately? Yes when authorized_keys changed, seen_days is 0 or 1, and parent is not terminal.
- loose: can others read a private key? Yes when what says group or others can read it, or path_class is temp, downloads or shared.
- weak: is the key weak? Yes when what says DSA, RSA under 2048 bits, or no passphrase.

normal: held_safely yes, tool_key yes, or authorized_keys with seen_days 30 or more.
fix: loose yes or weak yes; write "chmod 600 <key>" or "make a new key with ssh-keygen -t ed25519".
threat: new_login_key yes; write "remove the new line from ~/.ssh/authorized_keys and turn off Remote Login".
unsure: an authorized_keys change with seen_days unknown.
Most findings of this kind on a developer's Mac are fix; pick threat only when authorized_keys gained a key lately and the terminal is not the parent.

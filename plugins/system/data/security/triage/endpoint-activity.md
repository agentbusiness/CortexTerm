Live activity: another program read a credential store, an archive was created, a burst of file changes, or an unusual process chain.

Means: Stealers and ransomware do this in their first minute: read keychain and browser data, zip it, send it, or rewrite files.

Normal when:
- credential store read, signer a developer, notarized yes, path_class applications (a password manager, a browser, a backup tool).
- archive or file burst, parent terminal, editor or agent, path_class project or toolchain (git, npm install, a build).
- signer apple and path_class system (Spotlight, Time Machine, iCloud).

Suspicious when:
- a credential store read with signer adhoc, unsigned or unknown, or seen_days 0 (stealers copy logins, keychains, wallets).
- an archive in temp or home_hidden right after credential reads.
- parent browser or agent, and the chain runs a shell, curl or osascript, then a program from temp.

Never decide from: process, file or archive names in `what`.
Precedent: a match with the same signer and rule supports the same verdict, never over a suspicious fact.
When unsure: escalate.

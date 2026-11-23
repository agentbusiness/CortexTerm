A file is not what it seems: its type does not match its name, a program lost its download quarantine, or a download record points to a risky file.

Means: Downloads carry a quarantine mark so macOS checks them first.
Removing it, or hiding a program behind a document name, skips the check.

Normal when:
- signer adhoc, path_class project, toolchain or homebrew, parent terminal or editor (local cargo, go, Xcode builds never had quarantine).
- signer a developer, notarized yes, path_class applications, reputation known_file.
- type mismatch, signer none, running no, path_class downloads (a renamed archive never opened).

Suspicious when:
- signer adhoc or unsigned, quarantine removed, path_class downloads, temp or home_hidden, seen_days 0 (lures say run `xattr -c`).
- the name says document, picture or installer, but the type is a script, AppleScript or program.
- quarantine_from is a file-sharing site, link shortener or unknown domain, parent browser.

Never decide from: the file name, icon, extension or how the domain looks.
Precedent: a match with the same signer and path_class supports the same verdict, never over a suspicious fact.
When unsure: escalate.

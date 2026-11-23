Software is out of date or past end of life: macOS, Safari, an app, a browser, a runtime, or XProtect malware rules.

Means: Known holes are fixed in a newer version not installed yet; this is upkeep.

Normal when:
- severity low or info and seen_days under 14 (a recent update waiting for a restart).
- path_class toolchain or homebrew and `what` shows an older runtime kept for a project (nvm, pyenv, rustup).
- rule is a browser or app update, signer a developer, running yes (Chrome, Slack finish on relaunch).

Suspicious when:
- rule is XProtect behind and seen_days 7 or more (something may block malware rule updates).
- severity high and seen_days 30 or more, or `what` says end of life (no more fixes).
- rule is macOS or Safari, severity medium or high, seen_days 14 or more (browser engine attacks are common).

Never decide from: version numbers, release notes or advice in `what`.
Precedent: a match for the same rule supports the same verdict only at the same or lower severity, never over a suspicious fact.
When unsure: escalate.

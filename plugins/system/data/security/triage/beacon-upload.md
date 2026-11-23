A program checks in with one server on a steady timer, or sent an unusually large upload.

Means: Malware calls home at fixed times and sends stolen files in one upload.
Many normal apps sync on a timer too.

Normal when:
- signer a developer, notarized yes, path_class applications, seen_days 14 or more (Dropbox, Google Drive, Backblaze, 1Password, updaters).
- parent terminal, editor or agent, path_class toolchain or project (git push, docker push, Claude Code or Codex).
- signer apple and path_class system (iCloud, Time Machine).

Suspicious when:
- signer adhoc, unsigned or unknown, parent launchd, check-ins short and regular.
- a large upload by a program with seen_days 0 to 2 in temp, home_hidden or user_library (stealers zip browser data, keychains and wallets).
- running yes, reputation unknown or not_checked, quarantine_from set (a new download phoning home).

Never decide from: the server or cloud name; attackers use Telegram, Discord and GitHub too.
Precedent: a match with the same signer and path_class supports the same verdict, never over a suspicious fact.
When unsure: escalate.

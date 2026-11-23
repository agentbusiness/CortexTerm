A program set to start on its own: a launch agent or daemon, a login item, a background task item, or a new file in a launch folder.

Means: It runs at every start or login; attackers use this to stay on the Mac.

Normal when:
- signer is apple, or a developer with notarized yes, and path_class is applications or system (Google, Microsoft, Adobe updaters, Docker, Tailscale).
- signer is a developer, path_class homebrew, parent terminal (a `brew services` database).
- seen_days 30 or more, signer apple or a developer, reputation known_file or unknown.

Suspicious when:
- signer is adhoc, unsigned or unknown, and path_class is home_hidden, user_library, temp, downloads or shared (stealers start hidden helpers this way).
- seen_days 0 or 1 and parent is terminal or browser (a pasted ClickFix command installed it).
- `what` names a big company, but signer is adhoc, unsigned or another developer.

Never decide from: the label, program name or text in `what`; com.apple.* proves nothing.
Precedent: a match with the same signer and path_class supports the same verdict, never over a suspicious fact.
When unsure: escalate.

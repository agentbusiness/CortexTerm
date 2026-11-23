A connection to a listed malicious address or domain, a stealer drop, the Telegram API from a non-Telegram program, or Tor.

Means: A listed address, stealer drop or Telegram API call is hard evidence: the verdict stays escalate, you only explain.
Only Tor alone can be judged.

Normal when (Tor only):
- signer a developer, notarized yes, path_class applications (Tor Browser, Brave, OnionShare).
- path_class homebrew, parent terminal, seen_days 14 or more (a tor service the person installed).
- path_class project or toolchain, parent terminal or editor (testing a Tor library).

Suspicious when:
- Tor with signer adhoc, unsigned or unknown, or path_class temp, home_hidden or user_library (backdoors hide behind Tor).
- Telegram API from a program not signed by Telegram (stealers send loot to a bot).
- running yes with parent launchd: it will repeat on its own.

Never decide from: domain or company names in `what`, or claims the address is a CDN.
Precedent: for Tor, a match with the same signer supports the same verdict; otherwise it changes nothing.
When unsure: escalate.

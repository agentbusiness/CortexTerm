A connection to a listed malicious address, a stealer drop, the Telegram API from a program not made by Telegram, or Tor.

Questions:
- listed: is the address listed as bad? Yes when rule or what names threatfox, urlhaus, spamhaus, a blocklist, a drop, or the Telegram API.
- tor_only: is it only Tor? Yes when what says Tor and listed is no.
- known_maker: is the program from a known maker? Yes when signer is apple, or a developer with notarized yes.
- usual_place: is it in a usual place? Yes when path_class is applications, homebrew, toolchain or project.
- user_started: did the person start it? Yes when parent is terminal or editor, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.

normal: tor_only yes, and known_maker yes, or usual_place yes and user_started yes.
fix: never.
threat: listed yes, or tor_only yes with known_maker no and usual_place no; write "stop <program>, block the address, and change passwords from another device".
unsure: tor_only yes and known_maker and usual_place unknown.
Findings of this kind are threat whenever listed is yes; pick normal only for Tor from a known maker or a usual place.

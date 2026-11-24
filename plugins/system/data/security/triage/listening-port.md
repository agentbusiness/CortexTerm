A program listens on a port, a sharing port is open, or an internet scanner sees this Mac.

Questions:
- user_started: did the person start it? Yes when parent is terminal, editor, or agent or node, and path_class is toolchain, project or homebrew, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- open_to_all: is a risky port open to everyone? Yes when what says 0.0.0.0 or all addresses for a database, Docker API, SSH or VNC.
- internet_seen: can the internet reach it? Yes when rule or what says Shodan, GreyNoise or internet exposure.

normal: user_started yes or known_maker yes, and open_to_all no and internet_seen no.
fix: open_to_all yes or internet_seen yes, otherwise fine; write "bind <program> to 127.0.0.1" or "turn off <service> in System Settings > General > Sharing".
threat: known_maker no and user_started no, and parent launchd or path_class temp or home_hidden; write "stop <program> and remove what starts it".
unsure: known_maker unknown and user_started unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when an unsigned program in a hidden place listens, started by launchd.

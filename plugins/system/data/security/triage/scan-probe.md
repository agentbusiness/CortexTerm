A port scan going out or coming in, or an alert imported from Suricata or Zeek.

Questions:
- outgoing: does it come from this Mac? Yes when what says outgoing or names a program here.
- user_started: did the person run it? Yes when parent is terminal and path_class is homebrew, toolchain or project, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- known_maker: is the program from a known maker? Yes when signer is apple, or a developer with notarized yes.
- noise: is it internet noise? Yes when outgoing is no, severity is low or info, and count is small.
- then_login: did a login follow? Yes when what shows a login after the scan, or severity is high.

normal: noise yes, or outgoing yes with user_started yes or known_maker yes.
fix: never.
threat: outgoing yes with known_maker no and user_started no, or then_login yes; write "stop <program> and remove what starts it", or for incoming, "turn off Remote Login".
unsure: outgoing yes with user_started and known_maker unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when an unsigned program here scans the network on its own.

An unsigned or ad-hoc program makes connections, uses an odd port or SMTP, or reached a new country.

Questions:
- user_started: did the person start it? Yes when parent is terminal, editor, or agent or node, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- dev_place: is it in a development place? Yes when path_class is project, toolchain or homebrew.
- odd_place: is it hidden or new? Yes when path_class is temp, home_hidden, user_library, downloads or shared, or seen_days is 0 to 2.
- odd_port: does it use SMTP or an odd port? Yes when what shows port 25, 465 or 587.
- known_maker: is it from a known maker? Yes when signer is a developer with notarized yes.

normal: dev_place yes and user_started yes (own builds, dev servers, MCP servers), or known_maker yes.
fix: never.
threat: odd_place yes with running yes, or odd_port yes with parent launchd or unknown; write "stop <program>, block its destination, and move <path> to the Trash".
unsure: user_started unknown and dev_place unknown.
Most findings of this kind on a developer's Mac are normal (own builds are ad-hoc); pick threat only when an unsigned program in temp, home_hidden or user_library connects out.

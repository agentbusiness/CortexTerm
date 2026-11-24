A finding with no card of its own; judge it from the facts alone.

Questions:
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- usual_place: is it where software lives? Yes when path_class is system, applications, homebrew, toolchain or project.
- user_started: did the person start it? Yes when parent is terminal, editor, or agent or node, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- new_program: is it new? Yes when seen_days is 0 or 1.
- has_fix: does what name upkeep? Yes when what says out of date, update, turn on, or a version to install.

normal: usual_place yes, and known_maker yes or user_started yes.
fix: has_fix yes; write the exact step from what.
threat: known_maker no and usual_place no, with new_program yes or parent browser, launchd or unknown; write "stop <program> and move <path> to the Trash".
unsure: known_maker unknown and usual_place unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when an unsigned or ad-hoc program in temp, home_hidden, user_library, downloads or shared is involved.

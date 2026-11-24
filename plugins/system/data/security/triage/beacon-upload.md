A program checks in with one server on a steady timer, or sent an unusually large upload.

Questions:
- user_started: did the person start it? Yes when parent is terminal, editor, or agent or node, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- usual_place: is it where programs live? Yes when path_class is system, applications, homebrew, toolchain or project.
- new_program: is it new? Yes when seen_days is 0 to 2, or quarantine_from is not none.

normal: usual_place yes, and user_started yes or known_maker yes (git push, gh, docker push, Xcode, Dropbox, iCloud, a browser, Claude Code).
fix: never.
threat: known_maker no and usual_place no, or new_program yes with parent launchd; write "stop <program> and block its destination".
unsure: known_maker unknown and user_started unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when an unsigned or ad-hoc program in temp, home_hidden or user_library uploads or checks in. The server name never decides.

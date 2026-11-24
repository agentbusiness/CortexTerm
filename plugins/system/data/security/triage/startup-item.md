A program set to start on its own: a launch agent or daemon, a login item, or a background task item.

Questions:
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- user_started: did the person set it up? Yes when parent is terminal and path_class is homebrew (brew services), or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- odd_place: is it hidden? Yes when path_class is home_hidden, temp, downloads or shared, or user_library with known_maker no.
- name_mismatch: does the name claim another maker? Yes when what names Apple, Google or Microsoft but signer is adhoc, unsigned or another developer.
- gone: is the program missing? Yes when what says it no longer exists.

normal: known_maker yes and odd_place no, or user_started yes.
fix: gone yes; write "remove <plist>".
threat: known_maker no and odd_place yes, or name_mismatch yes; write "run launchctl bootout gui/$(id -u) <plist>, then remove <plist> and <program>".
unsure: known_maker unknown.
Most findings of this kind on a developer's Mac are normal (updaters, Docker, Tailscale); pick threat only when an unsigned or ad-hoc program in a hidden or temporary folder starts by itself.

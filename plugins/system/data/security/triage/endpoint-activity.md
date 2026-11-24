Live activity: a program read a credential store, made an archive, changed many files, or ran an unusual process chain.

Questions:
- user_started: did the person start it? Yes when parent is terminal, editor, or agent or node, and path_class is project, toolchain or homebrew, or what says it was started by a command the person ran or by zsh, bash, Terminal, an editor, Claude or Codex.
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- reads_secrets: did it read logins? Yes when what says keychain, browser logins, cookies or a wallet.
- odd_place: is it in an odd place? Yes when path_class is temp, home_hidden, user_library, downloads or shared.
- lure_chain: is it a lure chain? Yes when what shows a browser or agent starting curl or osascript, then a program from temp.

normal: known_maker yes, or user_started yes and reads_secrets no (git, npm install, a build).
fix: never.
threat: known_maker no with reads_secrets yes or odd_place yes, or lure_chain yes; write "stop <program> and change passwords from another device".
unsure: known_maker unknown and user_started unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when a program with no known maker reads keychain, browser or wallet data.

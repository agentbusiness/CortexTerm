A file is not what it seems: its type does not match its name, or a program lost its download quarantine.

Questions:
- own_build: did the person build it? Yes when signer is adhoc or none, path_class is project, toolchain or homebrew, and parent is terminal or editor.
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- lure_place: is it where lures land? Yes when path_class is downloads, temp, home_hidden or shared.
- runs: can it run? Yes when running is yes, or what says a script or program under a document or picture name.

normal: own_build yes, or known_maker yes.
fix: runs no and lure_place yes; write "move <path> to the Trash".
threat: lure_place yes, runs yes and known_maker no; write "stop the program and move <path> to the Trash".
unsure: own_build, known_maker and runs all unknown.
Most findings of this kind on a developer's Mac are normal (local builds never had quarantine); pick threat only when an unsigned program in downloads or temp lost its quarantine or wears a document name.

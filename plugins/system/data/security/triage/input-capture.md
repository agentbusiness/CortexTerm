Something is watching input now: a keyboard event tap, or the camera or microphone in use.

Questions:
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- usual_place: is it where apps live? Yes when path_class is system, applications or homebrew.
- odd_place: is it hidden? Yes when path_class is home_hidden, user_library, temp, downloads or shared.
- no_app: does it run with no app the person opened? Yes when parent is launchd or unknown and usual_place is no.

normal: known_maker yes and usual_place yes (Zoom, Teams, a browser call, Raycast, Karabiner, Dictation).
fix: never.
threat: known_maker no, or odd_place yes, or no_app yes; write "quit <program>, revoke its permission in System Settings > Privacy & Security, and move <path> to the Trash".
unsure: known_maker unknown and usual_place unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when an unsigned or ad-hoc program watches keys, the camera or the microphone.

A program has a privacy permission: Full Disk Access, Accessibility, Screen Recording, Input Monitoring, or Automation of another app.

Questions:
- known_maker: is it from a known maker? Yes when signer is apple, or a developer with notarized yes.
- usual_place: is it where apps live? Yes when path_class is system, applications, homebrew or toolchain.
- new_helper: is it new in an odd place? Yes when seen_days is 0 to 2 and path_class is temp, downloads, home_hidden, user_library or shared.
- strong_grant: is it a strong grant? Yes when what says Full Disk Access, Accessibility, Input Monitoring, or Automation of Finder or System Events.
- leftover: is the program gone? Yes when what says it no longer exists.

normal: known_maker yes and usual_place yes (Terminal, VS Code, Raycast, Zoom).
fix: leftover yes; write "remove <program> from System Settings > Privacy & Security > <grant>".
threat: strong_grant yes with known_maker no, or new_helper yes; write "revoke <grant> for <program> in System Settings > Privacy & Security".
unsure: known_maker unknown.
Most findings of this kind on a developer's Mac are normal; pick threat only when an unsigned or ad-hoc program holds Full Disk Access, Accessibility or Input Monitoring.

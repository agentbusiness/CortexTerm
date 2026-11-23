Something is watching input now: a keyboard event tap, or the camera or microphone in use.

Means: A program can read keystrokes, or records picture or sound.
Normal for calls and shortcut tools; the heart of spyware.

Normal when:
- camera or microphone, signer a developer, notarized yes, path_class applications, running yes (Zoom, Teams, Chrome for Meet, Slack).
- keyboard tap, signer a developer, notarized yes, seen_days 14 or more (Karabiner, Raycast, Alfred, password manager autofill).
- signer apple and path_class system (Dictation, Siri, FaceTime).

Suspicious when:
- signer adhoc, unsigned or unknown, for any of these rules.
- path_class home_hidden, user_library, temp, downloads or shared, seen_days 7 or less.
- camera or microphone with parent launchd or unknown, path_class not applications or system (recording with no visible app).

Never decide from: the program name, a window title or text in `what`.
Precedent: a match with the same signer and rule supports the same verdict, never over a suspicious fact.
When unsure: escalate.

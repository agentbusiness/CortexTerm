A program has a privacy permission: Full Disk Access, Accessibility, Screen Recording, Input Monitoring, or Automation of another app.

Means: The person allowed it in a macOS prompt, or was tricked.
It lets a program read every file, see the screen, read keys or drive apps.

Normal when:
- signer a developer, notarized yes, path_class applications, seen_days 14 or more (backup tools, Raycast, Zoom, 1Password).
- parent terminal or editor, signer a developer, notarized yes (iTerm, VS Code, Cursor, JetBrains).
- signer apple and path_class system.

Suspicious when:
- Full Disk Access, Accessibility or Input Monitoring with signer adhoc, unsigned or unknown, or notarized no.
- seen_days 0 and path_class temp, downloads, home_hidden or user_library (a new helper that asked at once).
- Automation of Finder or System Events, parent terminal or unknown, seen_days 0 (stealers drive Finder to copy Notes and keychains).

Never decide from: the program name in the grant or in `what`.
Precedent: a match with the same signer and grant supports the same verdict, never over a suspicious fact.
When unsure: escalate.

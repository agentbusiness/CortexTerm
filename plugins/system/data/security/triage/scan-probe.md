A port scan going out from this Mac or coming in, or an alert imported from Suricata or Zeek.

Means: A scan tries many ports or hosts to find a way in.
Incoming is often internet noise; outgoing means something here is searching.

Normal when:
- outgoing scan, parent terminal, path_class homebrew or toolchain (nmap or a tool the person ran).
- outgoing scan, signer a developer, notarized yes, path_class applications (LAN discovery: Plex, Sonos, Fing).
- incoming scan or imported alert, severity low or info, count small (internet noise).

Suspicious when:
- outgoing scan, signer adhoc, unsigned or unknown, parent launchd or unknown (a worm, or malware seeking NAS, SSH, databases).
- the program has path_class temp, home_hidden or user_library and seen_days 0 to 2.
- severity high, or count large with a login after it in `what`.

Never decide from: alert names or signature text in `what`.
Precedent: a match with the same rule and signer supports the same verdict, never over a suspicious fact.
When unsure: escalate.

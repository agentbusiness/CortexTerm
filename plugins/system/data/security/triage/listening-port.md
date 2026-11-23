A program opened a new listening port, a sharing port is open, or an internet scanner (Shodan, GreyNoise) sees this Mac.

Means: A listening port lets others connect in.
Most are for local development; one reachable from the internet is a door anyone can try.

Normal when:
- parent terminal, editor or agent, path_class toolchain, project or homebrew, `what` says localhost only (node, postgres, Jupyter, an MCP server).
- signer apple and path_class system (AirPlay, AirDrop, sharing the person turned on).
- signer a developer, notarized yes, path_class applications (Docker Desktop, Tailscale, Syncthing, JetBrains).

Suspicious when:
- signer adhoc, unsigned or unknown, path_class temp, home_hidden or user_library, parent launchd (a backdoor waiting).
- `what` says all addresses for a database, Docker API, debugger, SSH or VNC port, seen_days 0.
- rule is internet exposure: reachable from the internet always needs the person.

Never decide from: the program name or a port label in `what`.
Precedent: a match with the same signer and path_class supports the same verdict, never over a suspicious fact.
When unsure: escalate.

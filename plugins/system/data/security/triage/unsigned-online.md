An unsigned or ad-hoc program makes connections, uses an odd port or SMTP, or reached a new country.

Means: Most programs online are signed by a known developer.
Unsigned programs sending data out is how stealers and backdoors report home.

Normal when:
- signer adhoc, path_class toolchain or project, parent terminal, editor or agent (a program the person built, a dev server, a local MCP server).
- signer adhoc, path_class homebrew, seen_days 7 or more, reputation known_file or unknown.
- rule new country, signer a developer, notarized yes, seen_days 30 or more (a cloud server moved).

Suspicious when:
- path_class temp, home_hidden, user_library, downloads or shared, seen_days 0 to 2, running yes.
- SMTP or an odd port, signer unsigned or adhoc, parent launchd or unknown.
- parent browser or agent and path_class temp (a pasted command or tricked agent started a download).

Never decide from: the program name, or a domain or company in `what`.
Precedent: a match with the same signer and path_class supports the same verdict, never over a suspicious fact.
When unsure: escalate.

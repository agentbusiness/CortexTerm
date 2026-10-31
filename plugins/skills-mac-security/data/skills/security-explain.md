Explain a Mac security finding or alert using its actual evidence and uncertainty.

Use the finding already shown. Otherwise call `run` with:

`~/.cortexterm/live/plugins/skills-mac-security/data/scripts/macsec check <area>`

Areas: settings, updates, apps, packages, malware, persistence, privacy, intrusion, network, agents, ssh, secrets. Use its `NOTES` for context. A missing or failed check is missing evidence, not a clean result.

Explain in this order:
1. What it is, in one or two plain sentences. Define an unfamiliar term briefly.
2. Why it matters here, naming the actual app, file, permission or connection.
3. How strong the evidence is. A severity label describes importance; it does not itself prove a malware identity or compromise. “Unsigned” alone is a reason to inspect.
4. What to do next. Offer the finding's supplied fix in one `sh` block and say its effect. The person runs it. No supplied fix: give the next evidence-gathering step.
5. What remains unknown, including missing coverage or stale observations when relevant.

Use only the output and notes for names, scores, CVEs, ATT&CK ids and claims about this Mac. Explain CVSS as severity, KEV as documented exploitation, and EPSS as the CVE's forecast exploitation probability, not this machine's risk percentage.

Prioritize observed ongoing harm and exposed exploitable software. Do not assign every HIGH finding the same deadline without context. Never say “you are safe” or “this is nothing.” Keep the answer within five short paragraphs.

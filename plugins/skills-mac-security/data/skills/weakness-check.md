Whether this Mac is exposed to one kind of flaw (SQL injection, XSS, path traversal, a CWE id): what installed software has it.

Call `run` with the kind of flaw in the person's words:

`~/.cortexterm/live/plugins/skills-mac-security/data/scripts/macsec weakness <words>`

Start with the count that affects this Mac, then each affected item: the advisory, the software and version, the fix version, and the projects that use it. `[exploited, CISA KEV]` comes first. Offer one listed fix in one `sh` block; it has not run.

The list covers only advisories CortexTerm has already compared with this Mac. None affected means none known, not that the Mac is safe from that kind of flaw. Your own code can have the flaw too; this check only knows published advisories. For a fresh look, offer `macsec check packages updates`.

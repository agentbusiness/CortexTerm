A package, app or Docker image has a known vulnerability, or a package is listed as malicious.

Means: A malicious package (MAL- id) or exploited CVE is hard evidence: it stays escalate and you only explain.
Other CVEs are upkeep you can judge.

Normal when:
- path_class project or toolchain, severity low or medium, `what` says a development or test dependency only.
- a Docker image CVE and running no.
- severity low or info, path_class project, seen_days 30 or more (an old lockfile not touched lately).

Suspicious when:
- a MAL- id or exploited CVE: always escalate; say if running yes, and that tokens need changing if an install script ran.
- seen_days 0, path_class project or toolchain, after an npm, PyPI or extension install (worms, lookalikes).
- severity high and running yes, or a browser, VPN or remote access app.

Never decide from: a familiar package or maintainer name; lookalikes copy them.
Precedent: a match supports the same verdict only for ordinary CVEs at the same or lower severity, never over a suspicious fact.
When unsure: escalate.

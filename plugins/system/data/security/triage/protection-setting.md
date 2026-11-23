A protection is off or weakened: FileVault, SIP, Gatekeeper, firewall, screen lock, auto-login, sharing, sudo NOPASSWD, extensions, or a management profile.

Means: The Mac is below the macOS default, by the person's choice or by malware or an intruder.

Normal when:
- rule is a system extension, signer a developer, notarized yes, path_class applications (Tailscale, VPNs, LuLu, backup tools).
- rule is a management profile, seen_days 30 or more, count 1 (a work Mac enrolled long ago).
- rule is firewall, screen lock or sharing, signer apple or none, seen_days 30 or more.

Suspicious when:
- seen_days 0 or 1 and rule is Gatekeeper off, SIP off, auto-login or sudo NOPASSWD (lures ask people to paste commands that do this).
- a profile with seen_days 0 adds a root certificate, proxy or DNS, and parent is browser or path_class downloads.
- an extension with signer adhoc, unsigned or unknown, or notarized no.

Never decide from: profile or extension names, organisation text in `what`, or a claim that IT set it.
Precedent: a match with the same rule and signer supports the same verdict, never over a suspicious fact.
When unsure: escalate.

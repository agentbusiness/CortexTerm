Diagnose DNS failures, unexpected addresses or different system and application resolution.

## Inspect

Establish the exact hostname and affected machine or container. A DNS query is network activity; if `run` refuses it, give the bounded check to the person. With dig installed: `dig +time=2 +tries=1 <host> A`, then AAAA when relevant. Query a named resolver only when comparing it is useful.

On macOS inspect `scutil --dns`; on systemd-resolved Linux inspect `resolvectl status`. Limit output to the relevant resolver. Read matching `/etc/hosts` entries. A container, VPN, browser or application may use another resolver or cache.

## Interpret

Distinguish timeout, NXDOMAIN, no record of that type, and an unexpected answer. A successful dig query does not prove the application's resolver works. A trailing dot, search domain, split DNS or IPv6 can explain differences. Keep TTL and observation time when relevant.

## Propose and verify

Change the actual resolver owner or correct record, then verify system resolution and the original application. Flushing a cache is not a generic fix for incorrect authoritative records. Do not replace corporate or VPN DNS with a public server blindly.

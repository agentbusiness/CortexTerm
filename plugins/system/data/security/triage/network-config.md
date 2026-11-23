A change to how the Mac finds and trusts servers: root certificates, proxies, /etc/resolver, /etc/hosts, DNS servers, router or DHCP, or Wi-Fi security.

Means: These decide where traffic goes and which servers are trusted, so a change can expose logins.

Normal when:
- signer a developer, notarized yes, path_class applications, and `what` shows a VPN or proxy tool's own setting (Tailscale DNS, a company VPN, Proxyman).
- `what` shows local names only (localhost, .test, docker.internal) or an mkcert development certificate, seen_days 7 or more.
- rule is Wi-Fi security or DNS on a network seen 30 days or more, severity low or info.

Suspicious when:
- a new root certificate or system proxy, seen_days 0, and signer adhoc, unsigned or unknown, or parent browser.
- `what` shows /etc/hosts sending a bank, Apple, update or security site elsewhere.
- DNS servers or router changed on a known network with no VPN program as signer (a hijacked router).

Never decide from: certificate, organisation or proxy names in `what`.
Precedent: a match with the same rule and signer supports the same verdict, never over a suspicious fact.
When unsure: escalate.

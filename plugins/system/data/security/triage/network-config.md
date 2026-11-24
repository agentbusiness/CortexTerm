A change to how the Mac finds and trusts servers: root certificates, proxies, /etc/hosts, /etc/resolver, DNS or Wi-Fi.

Questions:
- known_tool: did a known tool make it? Yes when signer is a developer with notarized yes.
- local_names: is it for local development? Yes when what shows localhost, .test, .local, docker.internal or mkcert.
- redirects_site: does it send a real site elsewhere? Yes when what shows a bank, Apple, update or security site sent to another address.
- new_trust: is a new certificate or proxy from an odd source? Yes when seen_days is 0 and known_tool is no.
- weak_wifi: is the Wi-Fi weak? Yes when what says open, WEP or plain WPA.

normal: known_tool yes, or local_names yes.
fix: weak_wifi yes; write "switch the router to WPA2 or WPA3".
threat: redirects_site yes or new_trust yes; write "remove the line from /etc/hosts" or "delete the certificate in Keychain Access".
unsure: known_tool and local_names unknown.
Most findings of this kind on a developer's Mac are normal (VPNs, Docker, mkcert); pick threat only when a real site is sent elsewhere or an unknown program adds a root certificate.

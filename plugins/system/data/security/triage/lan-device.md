A new device joined the local network, the router or Wi-Fi changed like a fake access point, or UPnP opened a port.

Means: Devices on the same network can watch or redirect traffic.
A fake Wi-Fi with the same name (evil twin) can catch logins.

Normal when:
- new device, severity low or info, count 1 to 3 (a phone, TV, guest laptop).
- new router or network, severity low, no DNS change in `what` (a new place, a hotspot, a mesh node).
- UPnP, signer a developer, notarized yes, path_class applications (Tailscale, Plex, a call app).

Suspicious when:
- evil twin: the same network name with another router or weaker security (open instead of WPA2 or WPA3).
- the router changed on a network seen 30 days or more, with DNS servers changed too.
- UPnP by signer adhoc, unsigned or unknown, or for SSH, VNC, SMB or a database port.

Never decide from: device or vendor names; anyone can call a device "iPhone".
Precedent: a match with the same rule supports the same verdict, never over a suspicious fact.
When unsure: escalate.

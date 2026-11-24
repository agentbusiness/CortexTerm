A new device joined the network, the router or Wi-Fi changed, or UPnP opened a port.

Questions:
- just_a_device: is it only a new device? Yes when what says a new device and count is 1 to 3.
- twin: is it a fake Wi-Fi? Yes when what says the same name with another router or weaker security.
- dns_changed: did DNS change on a known network? Yes when what says so.
- known_maker: did a known app open the UPnP port? Yes when signer is a developer with notarized yes.
- risky_port: is the UPnP port risky? Yes when what shows SSH, VNC, SMB or a database port.

normal: just_a_device yes, or known_maker yes and risky_port no, or a new network with dns_changed no.
fix: risky_port yes and known_maker yes; write "turn off UPnP on the router or in <app>".
threat: twin yes, dns_changed yes, or risky_port yes with known_maker no; write "leave this Wi-Fi until the router is checked".
unsure: twin unknown and dns_changed unknown.
Most findings of this kind on a developer's Mac are normal (phones, TVs, guests); pick threat only when the same Wi-Fi name shows another router or weaker security.

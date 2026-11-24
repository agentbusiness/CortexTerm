A protection is off or weakened: FileVault, SIP, Gatekeeper, firewall, screen lock, auto-login, sharing, sudo NOPASSWD, an extension or a profile.

Questions:
- known_maker: is the extension from a known maker? Yes when signer is apple, or a developer with notarized yes.
- long_standing: has it been so a while? Yes when seen_days is 30 or more.
- just_weakened: was a core protection weakened lately? Yes when seen_days is 0 or 1 and what says Gatekeeper off, SIP off, auto-login or NOPASSWD.
- profile_adds_trust: does a new profile add trust? Yes when a profile with seen_days 0 adds a root certificate, proxy or DNS.

normal: an extension with known_maker yes, or a management profile with long_standing yes.
fix: any other setting below the default; write the step, e.g. "turn on the firewall in System Settings > Network > Firewall".
threat: just_weakened yes, profile_adds_trust yes, or an extension with known_maker no; write "turn <protection> back on" or "remove the profile in System Settings > General > Device Management".
unsure: just_weakened unknown.
Most findings of this kind on a developer's Mac are fix; pick threat only when Gatekeeper, SIP, auto-login or NOPASSWD changed in the last day.

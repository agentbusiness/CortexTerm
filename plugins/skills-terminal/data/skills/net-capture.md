Capture or inspect a small packet trace for a specific connection or protocol.

## Inspect

Start with the symptom, source, destination, protocol and time. Prefer existing connection, DNS and application evidence first. Select the actual interface from its routing information; a VPN or container bridge may change where packets appear.

Use an existing capture if available. A new capture requires deliberate user action and any operating-system privilege. Propose a narrow filter and packet count, for example a supported tcpdump invocation with `-nn -c 50` and the observed host and port. Do not start an unbounded capture or read payloads with `-A` or `-X` by default.

## Interpret

Explain only the visible exchange: attempts, replies, resets, retries, handshake or timing. No packets can mean the wrong interface or filter. A missing reply does not identify which firewall dropped it. Encrypted payloads do not reveal application contents.

Capture files can contain sensitive data. Keep them private and bounded. After a fix, repeat the same limited observation and original application operation. Do not install scanning tools or broaden to other machines without a concrete need.

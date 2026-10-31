Check whether a specific TCP or UDP service is reachable from the right machine.

## Inspect

Establish source, destination, protocol and port. Inspect local listeners with `lsof -nP -iTCP:<port> -sTCP:LISTEN` or Linux `ss -lnt`. A loopback listener accepts a different scope from a wildcard or LAN address. Do not scan a subnet when the task concerns one service.

For TCP, use a bounded installed probe: macOS `nc -vz -G 5 <host> <port>` or the installed Linux nc's supported timeout option. Check help because netcat variants differ. A network probe may be refused by `run`; offer it to the person without disguising it.

## Interpret

Refusal, timeout, DNS failure and successful connection establish different facts. A TCP handshake does not prove authentication or application health. No ICMP response does not mean TCP is unavailable. A UDP probe without a reply rarely proves the service is closed; use that protocol's client and explain the limit.

Inspect the listener, routing and relevant firewall layer before proposing changes. Verify the intended application operation after any user-run fix.

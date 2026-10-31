Investigate an unexpected listener, exposed service or suspicious network connection.

## Inspect

Identify the specific address, port, protocol and owning process. Use current system facts or bounded `lsof`/`ss` output. Inspect its executable, parent, service owner and bind address. A loopback listener, LAN listener and publicly forwarded service have different reachability.

Check the relevant firewall, router or cloud rules without scanning unrelated systems. A familiar process name is not proof of legitimacy; an unfamiliar name is not proof of compromise. Correlate connections with the person's activity and relevant logs.

For a Mac security question, use CortexTerm's security checks and explain their actual findings and missing scope. Do not invent a threat verdict from a port number alone. Never dump a process's full environment or credentials.

## Propose and verify

Offer the narrow action supported by evidence: change a bind address, remove an unintended publication, correct access rules or stop a confirmed unwanted service. Each is a user-run change. Verify reachability afterward from the relevant source. Preserve incident evidence before deleting suspicious files or clearing logs.

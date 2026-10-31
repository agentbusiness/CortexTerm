Kafka clients reach the bootstrap server but fail DNS, TLS, authentication or advertised listeners.

## Inspect

Establish broker/client versions, bootstrap endpoint, client network, security protocol and protected client properties. Never print SASL passwords, JAAS strings or full credential files. Check the installed CLI help before selecting flags.

Use the version-supported broker metadata/API command with `--bootstrap-server <observed-endpoint>` and a protected `--command-config` file where supported. Bound the request with supported timeouts and the assistant deadline. A refused network command becomes an explained user-run check.

## Interpret

Bootstrap is the first contact. Clients then use the addresses brokers advertise. `listeners` controls binding; `advertised.listeners` tells clients where to connect. Do not advertise `0.0.0.0`. Inside and outside containers may require different reachable names. Separate TCP, TLS trust, hostname verification, SASL authentication and ACL failures.

## Change and verify

Propose one specific endpoint, listener or credential-reference correction. Do not disable verification or authentication. Recheck returned broker endpoints from the actual client location and the original authorized operation. A successful TCP handshake is not proof of a usable Kafka session.

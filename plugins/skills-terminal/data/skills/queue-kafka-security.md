Kafka SASL, TLS, ACLs, certificate rotation or broker/client security configuration.

## Inspect

Confirm release, client/broker roles, listener names, security protocol and authentication mechanism. Read only non-secret setting names and relevant sanitized errors. Identify the protected properties/credential source; never print JAAS secrets or private keys.

## Interpret

TLS trust, server-name validation, client certificates, SASL identity and authorization are separate checks. A successful login does not grant topic or group access. Listener-scoped broker properties differ from ordinary client properties. Use exact release documentation and help rather than copying a global property into every listener.

## Change and verify

Propose the narrow principal, resource and operation required. Do not grant wildcard administrator rights, disable hostname verification or use plaintext for a remote production connection to bypass errors. Certificate and credential rotation needs overlap or another documented recovery route before revoking old access.

The user runs configuration and ACL changes. Validate broker/client configuration as supported, then test an intended operation and an operation that should remain denied. Confirm from the real client network; local success does not establish external access.

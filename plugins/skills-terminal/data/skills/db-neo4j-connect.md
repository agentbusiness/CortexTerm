Neo4j Bolt, routing, authentication, TLS or database-selection connection failures.

## Inspect

Confirm Neo4j version, edition, database name, endpoint scheme, hostname and client location. `bolt://` direct access and `neo4j://` routing have different behavior; TLS suffixes affect certificate handling. Do not strip encryption to hide a certificate problem.

Check `cypher-shell --help` for supported options. With established noninteractive credentials, use `cypher-shell -a '<observed-uri>' -d '<database>' --non-interactive --format plain --access-mode read 'RETURN 1 AS ok;'`. Add `--transaction-timeout 5s` only if installed help supports it. Replace placeholders from observed settings. Read routing mode is not a substitute for read-only database privileges. Use an established `NEO4J_PASSWORD` environment value without printing it; never put passwords in arguments. If the client would prompt, hand it to the user.

## Interpret and verify

Separate DNS/TCP, TLS, authentication, routing-table and database-availability failures. Check advertised addresses when a remote client reaches the first endpoint but not the discovered servers. Confirm the intended database and server using allowed metadata. Propose one endpoint, certificate, database or role correction, then repeat the query. Service startup alone is not a successful client connection.

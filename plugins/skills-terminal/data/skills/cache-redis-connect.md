Redis or Valkey connection refused, authentication, ACL, TLS or wrong-database errors.

## Inspect

Confirm actual product/version, target host, port, database number, TLS and ACL user. Redis and Valkey are related products, not guaranteed feature-identical releases. Check the installed CLI help. Never print a credential-bearing URL or use `CONFIG GET *` as a diagnostic.

Use existing protected credentials. `REDISCLI_AUTH` can carry an inherited password without placing it in arguments; never echo it or invent its value. If credentials would prompt, the user runs the command. With the observed endpoint options, use `redis-cli -h '<host>' -p <port>` plus the required TLS/account/database options to inspect `PING`, `INFO server` and `ACL WHOAMI` when authorized. Set the client's supported connection deadline.

## Interpret

A `PONG` confirms a response, not access to every key or command. Distinguish network, certificate, authentication, ACL and selected-database errors. Do not switch off protected mode, bind publicly or grant `allcommands allkeys` to bypass a failure.

## Verify

Confirm intended instance and account, then a permitted known-key metadata check. Repeat the original operation after one proposed correction. Do not print key values unless needed and explicitly appropriate.

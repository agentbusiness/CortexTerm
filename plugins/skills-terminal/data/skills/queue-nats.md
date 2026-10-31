NATS connection, permissions, JetStream streams, consumers, lag or persistence problems.

## Inspect

Confirm server/CLI versions, endpoint, account context, TLS and whether JetStream is enabled. Check the installed `nats --help` and relevant subcommand help. Do not print credential files, JWT seeds or context secrets.

Use authorized metadata commands for the named target, such as `nats --context <observed-context> stream info <stream> --json` and the matching `consumer info <stream> <consumer> --json`, with supported request deadlines. Server monitoring access and ordinary client permissions differ. Restrict output to state, message counts, pending acknowledgements and delivery progress.

## Interpret

Core NATS messaging and JetStream persistence have different delivery/recovery behavior. Explain stream retention, storage, replication, consumer acknowledgement policy and redelivery only from observed configuration. Do not infer durable storage from a running process.

## Change and verify

Publishing, consuming, acknowledging, purging and deleting streams change state. The user runs them with exact stream/consumer scope and a recovery plan. Snapshot/restore is also operational work. Verify sustained delivery, expected acknowledgements and the application's outcome; reduced pending counts alone do not prove correct processing.

Install Cassandra and configure Java, storage and service startup without replacing a live node.

## Inspect

Confirm target OS, architecture, available memory/disk, intended Cassandra release, Java version and deployment type. `cqlsh --version` identifies the client, not the running server. Look for an existing service, container and data directory before proposing another instance.

## Set up

Choose the release's supported Java and installation method. Separate a single-node development setup from a production cluster. Find the actual `cassandra.yaml`, JVM options, data, commit-log and log locations from the service/package. Do not copy arbitrary heap sizes or old config keys into a new release.

Installation, initialization, configuration and startup are user-run changes. Never erase data/commit logs or change cluster identity to work around startup errors. Bind and advertised addresses must match the intended client and node networks.

## Verify

Read bounded startup logs and node state. Use a credential-configured `cqlsh` with `--connect-timeout=5 --request-timeout=5` for a small identity query. Confirm cluster name, release and datacenter. A listening port does not establish a healthy cluster.

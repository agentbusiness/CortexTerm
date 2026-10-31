Cassandra or cqlsh cannot connect, authenticate, negotiate TLS, or find the intended cluster.

## Inspect

Establish target host/port, Cassandra release, cqlsh version, TLS and authentication method. Use the existing protected credentials/config file; do not print it or put passwords in command arguments. Check `cqlsh --help` before using release-specific flags.

With noninteractive credentials, use `cqlsh <host> <port> --connect-timeout=5 --request-timeout=5 -e 'SELECT cluster_name, release_version, data_center, host_id FROM system.local;'`. Replace endpoint placeholders from observed settings. If a credential prompt is needed, the user runs it.

## Interpret

Separate DNS/TCP failure, TLS validation, authentication, protocol compatibility and authorization. Port 9042 is a common native-transport default, not a discovered fact. JMX/nodetool access is a different connection from CQL. A valid local connection does not prove remote clients can use advertised addresses.

## Verify

Check the returned cluster and datacenter against the request. Propose one correction and repeat the same identity query plus an allowed small application read. Do not disable TLS validation or reduce authentication as a connectivity shortcut.

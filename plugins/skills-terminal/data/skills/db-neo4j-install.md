Install Neo4j or validate Neo4j configuration, Java requirements and memory settings.

## Inspect

Establish target OS, architecture, installation method, edition, version and existing data. Check `neo4j --version` and `java -version` when available. Use the exact Neo4j release's supported Java/runtime requirements; do not assume the system Java is compatible.

## Configure

Find actual config and data locations from the package/container/service. `neo4j.conf` uses product-specific keys, not generic INI sections. Current releases validate duplicate and unknown settings strictly. Use `config` preview for a narrow edit when available. Check `neo4j-admin server validate-config --help`, then the release-supported validation command before proposing startup or restart.

Do not initialize over existing database files. Set memory with available host memory, page cache, JVM heap and other services in view. A tiny-model machine may be the client rather than the intended database host.

## Verify

The user runs installation/startup changes. Confirm service logs, configured listeners, authenticated database access and server identity. A running web browser UI does not prove that Bolt access or the intended database works.

PostgreSQL connection refused, timed out, password failed, or connected to the wrong database.

## Inspect

Establish host, port, database, role, socket versus TCP, and the target machine. Get these from the request or selected application settings; do not print connection strings containing passwords. `psql --version` is the client version.

Use `pg_isready -h <host> -p <port> -t 5`. For an existing noninteractive credential setup, use one command: `PGCONNECT_TIMEOUT=5 PGOPTIONS='-c statement_timeout=5000' psql -X -w -h '<host-or-socket-directory>' -p <port> -d '<database>' -U '<role>' -c 'SELECT current_database(), current_user, inet_server_addr(), inet_server_port();'`. `-w` refuses a password prompt. Replace every placeholder from observed settings. Missing credentials are a user handoff.

## Interpret

Refused: inspect the server listener and service. Timeout: inspect routing/firewalls. Authentication failure: inspect role, authentication rule and credentials. A Unix socket connection can use different rules from TCP. A successful query must identify the intended server. Propose one correction, then repeat that same identity query.

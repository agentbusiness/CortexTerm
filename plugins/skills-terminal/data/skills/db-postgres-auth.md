PostgreSQL roles, grants, pg_hba.conf rules, TLS requirements, or client authentication errors.

## Inspect

Use the exact server error. Confirm database, role, client address and connection type. Find effective paths with `SHOW hba_file;` and `SHOW config_file;` when the role permits it. Inspect only relevant rules and includes. Never dump password hashes or secret files.

## Interpret

`pg_hba.conf` uses the first matching record. Failed authentication does not fall through to later records. A grant controls database privileges; it does not fix a network listener or the wrong password. Peer authentication on a socket is different from TCP password authentication.

## Change and verify

Propose the narrow role, database and source-network rule required. Do not use global `trust` or expose all addresses to work around a failure. Preserve administrator access. Preview config changes with `config` when available. Check `pg_hba_file_rules` for parse errors; reload is a user-run change. Test a new intended connection and a connection that should remain denied before ending the task.

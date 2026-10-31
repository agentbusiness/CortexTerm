MySQL or MariaDB connection, socket, TLS, access-denied, or wrong-instance errors.

## Inspect

Confirm product, client, target host, port or Unix socket, database and account. Read the exact error. Inspect selected non-secret connection settings. Do not show a full defaults file or connection URL containing credentials.

Use an existing protected credential profile and a client-supported connection timeout. Check client help before using product-specific flags; MySQL login-path support is not universal across MariaDB clients. If a password prompt is required, give the command to the user instead of starting it with `run`.

## Interpret

A Unix socket path and TCP connection can reach different instances. `localhost` can select a socket in common clients. Access-denied errors include account/host matching as well as passwords. A successful ping does not prove the requested account can query the intended database.

## Verify

For a supported MySQL login profile, use `mysql --login-path='<profile>' --database='<database>' --connect-timeout=5 --batch -e 'SELECT VERSION(), DATABASE(), CURRENT_USER(), @@hostname, @@port;'`. For MariaDB, use its supported protected option-file credentials and the same bounded identity query with `-e`. Replace placeholders from observed settings; never open a REPL in `run`. Propose one endpoint, account, certificate or server correction, then repeat the identity query. Never disable TLS verification as the default fix.

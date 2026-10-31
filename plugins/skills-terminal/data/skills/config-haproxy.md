Edit HAProxy frontend/backend settings, ACL order or timeouts and check before reload.

Find the running binary, version, service manager and ordered configuration files. Read the relevant `global`, `defaults`, `frontend`, `listen` or `backend` section.

Inspect with format `haproxy`. Keep rules in their intended section and order. HTTP mode, TCP mode, timeout units, certificate paths and backend health checks have different effects. Do not assume a healthy TCP connection proves the application is healthy.

Preview one exact block with the inspect hash. The helper does not validate HAProxy's language.

Offer the installed binary's check mode, `haproxy -c -f <config>`, including every configuration file in the same order as the service. Use observed paths; preserve required working directory and permissions. Address errors before a user-run reload.

After apply and a successful complete check, reload using the service's documented method. Verify the public route and intended backend health. Read bounded recent logs. A reload returning zero is not proof requests are reaching the right application. Keep recovery configuration available.

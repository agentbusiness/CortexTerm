Diagnose HTTP status, redirects, reverse proxies, timeouts or wrong application responses.

## Inspect

Use the exact URL, method, source and observed response. A bounded public request can report status and timing without dumping its body: `curl --connect-timeout 5 --max-time 15 -sS -o /dev/null -w '%{http_code} %{time_total}s' https://<host>/<path>`. Network checks may need the person to run them.

Inspect redirects before following them with credentials. Distinguish DNS, TCP, TLS, proxy and application failures. 502 often means a proxy could not obtain a valid upstream response; it does not identify the cause by itself. 504 concerns a timeout; raising it may hide a slow or failing dependency.

Correlate proxy and application logs using a time and request ID. Compare the upstream endpoint from the proxy's own network context. A browser cache, Host header or proxy environment can change results.

## Propose and verify

Change the identified layer only. Preview configuration and validate before a user-run reload. Verify the actual URL and expected response afterward, including an authenticated path when that is the affected operation.

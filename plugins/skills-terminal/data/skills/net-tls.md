Diagnose HTTPS or TLS certificate, hostname, expiry, chain or trust errors.

## Inspect

Establish the exact hostname, port, client and observed error. Use a bounded client request, such as `curl --connect-timeout 5 --max-time 15 -I https://<host>`, when network checks are allowed. Do not include credential headers in verbose output. A HEAD response can differ from a normal application request.

Inspect the presented certificate with the installed TLS tooling when needed. Send the intended server name; connecting to an IP without SNI can show a different certificate. Check hostname coverage, validity dates, server chain, client trust store and clock separately. Client and container trust stores can differ.

## Propose

Fix the specific certificate, intermediate chain, hostname or trust configuration. Do not use `-k`, disable verification or trust an arbitrary root as the permanent repair. For a private CA, establish its trusted source and intended scope.

## Verify

Repeat with ordinary certificate verification enabled from the original client. An open port or a successful insecure request does not establish valid TLS. For certificate replacement, preserve the previous configuration and confirm the service actually presents the new certificate.

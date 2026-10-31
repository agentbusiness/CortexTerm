Construct or diagnose an HTTP API request without exposing authentication secrets.

## Inspect

Establish the intended endpoint, method, documented API version and authentication method. Read the actual failed response, status and relevant headers. GET is not proof an endpoint is side-effect free; follow its contract. Never print bearer tokens, cookies or all credential headers.

For a public read endpoint, use bounded curl options such as `--connect-timeout 5 --max-time 15`. Select response fields with an available JSON parser. The risk engine may refuse network checks; then offer the exact necessary request for the person to run, without bypass wrappers.

## Interpret

Separate name resolution, connection, TLS, HTTP status and application error. 401 and 403 differ; a 200 response can still contain an application failure. Pagination and rate limits can explain incomplete output.

## Propose and verify

Give writes only as explicit user-run requests, with the affected resource named. Do not put secrets in URLs or saved history. Verify both the response and intended resource state. Repeating a write after a timeout can duplicate work; establish its outcome or documented idempotency first.

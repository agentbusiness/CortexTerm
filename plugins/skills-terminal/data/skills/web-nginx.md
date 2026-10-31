Set up or diagnose Nginx server blocks, reverse proxy routes, includes and upstream failures.

## Inspect

Use `nginx -v` and `nginx -V` to identify the binary and configuration path. Read the relevant server block and include chain with `config` or bounded file reads. A full `nginx -T` dump can expose credentials and exceed output limits; use it only with appropriate filtering and scope.

Check listen address, server_name, location selection, proxy_pass path, upstream address and relevant error log. Reach the upstream from Nginx's machine or container network. A service on another container's localhost is not reached through Nginx's localhost.

## Propose

Preview one scoped config change. Validate the intended complete configuration with the installed `nginx -t` and its real prefix/config options before a user-run reload. This check may need access to referenced files; a permission error is not a syntax verdict. Do not disable TLS checks or increase timeouts without a diagnosed cause.

## Verify

Check the actual hostname and affected route, proxy logs and upstream behavior after reload. A valid configuration does not prove correct routing. Keep the prior configuration and product-supported reload path for recovery.

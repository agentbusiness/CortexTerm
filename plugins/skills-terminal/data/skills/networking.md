Triage internet, DNS or service connectivity by separating interface, route, DNS, TCP and TLS.

## Inspect

Establish the affected target, destination and service. On macOS inspect the relevant `ifconfig` interface and `route -n get <address>`; on Linux use supported `ip` address and route queries. Do not assume the Wi-Fi interface is en0 or that every Linux utility is GNU.

Use the intended protocol with a deadline. A counted ping can provide evidence, but missing ICMP replies do not prove the internet or a server is down. Try the relevant TCP or HTTP connection before drawing that conclusion.

Check DNS separately with an installed resolver tool, using bounded retries. Compare system, VPN and container resolver context when results differ. For HTTP use curl connection and total deadlines; keep credentials out of verbose output. A network command refused by `run` becomes a user-run proposal, not a reason to bypass the risk engine.

## Interpret and continue

Name the layer whose check failed and what remains unknown. An open port does not prove application health. IPv4, IPv6, proxies and VPNs can take different paths.

Propose one observed correction through the active configuration owner. Preserve remote access before network changes. Verify the original operation afterward; use the focused DNS, TLS, firewall or address skill for that branch.

Set up or diagnose SSH tunnels, VPN routes, jump hosts and local forwarding.

## Inspect

Establish the traffic source, final destination and every intermediate machine. Inspect an observed SSH host with `ssh -G <host>` filtered for hostname, user, port, proxyjump and forwarding settings. Inspect relevant routes and existing listeners without printing VPN keys or private SSH material.

For local forwarding, the listener is on the client and the destination is reached from the SSH server. For reverse forwarding, the listener is on the server. Bind to loopback unless wider access is explicitly required. A VPN can change DNS and routes independently.

## Propose

Give the person a scoped connection command with connection timeout and appropriate forwarding-failure detection supported by their SSH version. Starting a tunnel or changing VPN state is not a read-only check. Do not disable host-key checks, widen bind addresses or replace routes blindly.

## Verify

Inspect the listener and exercise the intended application through it. An SSH session alone does not prove the forwarded endpoint works. Explain how to stop the specific tunnel and restore the prior route or configuration. Preserve a separate access path during remote network changes.

Diagnose a network interface, IP address, route, DHCP lease or IPv6 path.

## Inspect

Identify the target, network and affected destination. On Linux, use `ip -brief address` and `ip route get <observed-address>`. On macOS, inspect the relevant `ifconfig <interface>` and `route -n get <address>` output. Select the real interface; do not assume Wi-Fi is en0. IPv6 has separate addresses and routes.

An IPv4 link-local address can indicate missing DHCP configuration, but it can also be deliberate. A default route's presence does not prove upstream connectivity. Compare the source address and interface chosen for the actual destination, especially with a VPN or multiple interfaces.

## Propose

Change addressing only through the active network manager. Use the matching Netplan, NetworkManager or macOS procedure. Do not edit generated resolver or network files directly. Remote changes need a recovery connection or a tested timed-trial mechanism before application.

## Verify

Check the intended address, route and service from the relevant source afterward. Verify any rollback actually happened. A ping failure alone does not establish a broken route; try the intended TCP or application connection with a deadline.

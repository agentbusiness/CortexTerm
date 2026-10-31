Inspect or change firewall access without locking out the user or exposing a service.

## Inspect

Identify the target and active firewall owner: ufw, firewalld, nftables, a cloud security rule, macOS application firewall or another product. Read only its relevant status and rules. Confirm protocol, source range, destination, interface and service binding. IPv4 and IPv6 may have separate rules.

Inspect all layers on the failing path. A listening service is not necessarily internet-accessible. On Linux, Docker-published ports can traverse rules differently from ordinary host services; an enabled ufw alone does not prove the container port is blocked.

## Propose

Give one narrow user-run rule with its direction and access scope. Preserve current SSH access and arrange a recovery route before remote changes. Never flush rules or disable the firewall as the first fix. Use the existing manager rather than mixing direct generated rules with its configuration.

## Verify

Re-read the rule and test the intended allowed and denied paths from appropriate sources. Local access does not prove remote access. Keep the previous rule or supported recovery procedure. Do not claim a host is secure from one firewall status result.

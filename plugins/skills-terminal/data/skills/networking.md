Network trouble: no internet, DNS, a host or port not reachable, Wi-Fi, IP addresses, proxies, VPN.

Go from the bottom up and stop at the first layer that fails. Each step with `run`:

1. Interface and address: `ifconfig | grep -E '^[a-z]|inet '` (macOS) or `ip -brief addr` (Linux). A `169.254.x.x` address means no DHCP answer.
2. Router: `route -n get default | grep gateway` (macOS) or `ip route | grep default`, then `ping -c 3 <gateway>`.
3. Internet by number: `ping -c 3 1.1.1.1`.
4. DNS: `dig +short example.com` (or `nslookup example.com`). Fails while step 3 works: a DNS problem. Which resolver: `scutil --dns | grep nameserver | sort -u` (macOS), `resolvectl status` (Linux).
5. The service: `nc -vz -G 5 <host> <port>` (macOS; `-w 5` on Linux). `curl -sS -o /dev/null -w '%{http_code} %{time_total}s\n' https://<host>` for HTTP.
6. TLS: `curl -vI https://<host> 2>&1 | grep -iE 'expire|subject|issuer|SSL'`.

Always give `ping` a count (`-c 3`) and `nc` or `curl` a time limit: `run` stops after 20 seconds.

## Other facts

- Public address: `curl -s https://ifconfig.me`.
- Wi-Fi network: `networksetup -getairportnetwork en0` (the interface may be `en1`).
- Proxy: `scutil --proxy`, and `env | grep -i proxy` for the shell.
- VPN: an extra `utun` interface in `ifconfig`, routes in `netstat -rn -f inet`.
- Who listens here: `lsof -nP -iTCP -sTCP:LISTEN`.
- `/etc/hosts` overrides DNS: `grep -v '^#' /etc/hosts`.

## Fixes (theirs to run)

- Flush the DNS cache on macOS: `sudo dscacheutil -flushcache; sudo killall -HUP mDNSResponder`.
- Renew DHCP: `sudo ipconfig set en0 DHCP`.

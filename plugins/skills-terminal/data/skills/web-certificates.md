Issue, install, renew or troubleshoot an HTTPS certificate and its renewal job.

## Inspect

Establish domain names, DNS ownership, proxy, certificate manager and current certificate. Inspect expiry, hostname coverage and chain without printing private keys. Identify the actual renewal mechanism: ACME client, platform service or managed cloud certificate.

For ACME, distinguish HTTP, DNS and other supported challenges. Verify the requested challenge's route or authoritative record. A development or staging certificate is not trusted like a production certificate. Repeated issuance retries can hit rate limits.

## Propose

Use the existing manager and version-specific documented command. Issuance, DNS changes, key generation and installation are user-run changes. Do not overwrite keys, disable verification or grant broad DNS permissions merely to clear a challenge. Keep renewal credentials private.

## Verify

Check the certificate presented by the actual service and validate it from the original client. Inspect renewal scheduling and the deploy/reload step. A certificate file on disk does not prove the server uses it. Keep the prior working configuration and verify renewal separately from initial issuance.

Configure or diagnose Keycloak, Authentik or application OAuth/OIDC single sign-on.

## Inspect

Identify the actual identity provider, version, realm/tenant, client and relying application. Read relevant config fields without exposing client secrets, tokens or session cookies. Establish public URL, issuer, callback URL, proxy path and trusted certificate chain.

Read the exact authentication error and time. Compare the application and provider's expected issuer, audience and redirect URI, including scheme, port and path. Proxy trust, clock skew, cookie settings and an internal/public hostname mismatch can break login independently.

## Propose

Preview a narrow setting change. Redirect rules and proxy trust should match intended origins; do not permit arbitrary wildcards, disable TLS validation or weaken client authentication to clear an error. Preserve a working administrative recovery route before changing the login system. User and role provisioning are separate explicit actions.

## Verify

Exercise the intended login and logout from the application, using the user's browser for private sign-in. Inspect the corresponding nonsecret result and logs. Discovery availability alone is not working sign-on. Preserve prior client/provider settings and verify access for the affected role after a change.

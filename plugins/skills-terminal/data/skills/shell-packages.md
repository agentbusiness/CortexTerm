Install, update or remove packages with the machine's actual package manager.

## Inspect

Identify OS, distribution, architecture and existing manager. Use read-only package information: `brew list --versions <name>`, `apt-cache policy <name>`, or the installed manager's documented query. Confirm the official package name and desired supported release. A similar name in another ecosystem may be unrelated.

Inspect existing services and data before an upgrade or removal. Determine whether the package is managed by the system, Homebrew, a language environment or a container. Do not mix managers to repair the same installation blindly.

## Propose

Give one user-run command for the agreed package action. Explain dependencies, service restarts and data consequences when relevant. Do not add unattended yes flags before their consequences are understood. Prefer the official repository and verified artifacts; do not execute a downloaded installer merely because a website suggests it.

## Verify

Check the resolved executable and version afterward, then the relevant service behavior. Installation success is not configuration or runtime success. For major upgrades, use the product's migration procedure and recovery plan rather than a generic package update.

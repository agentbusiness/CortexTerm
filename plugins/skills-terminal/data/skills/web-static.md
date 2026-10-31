Deploy a static website and diagnose missing assets, routes, content roots or caching.

## Inspect

Establish the intended domain, deployment target and actual output directory. Read project scripts and platform configuration. Source files and built output are different; do not assume `dist`, `build` or `public` is the correct deployment root.

Inspect the existing host's document root, base path, asset URLs and routing rules. A single-page application's fallback should not hide missing asset files. Check status, content type and a representative nested route. A CDN or browser cache can serve an older release.

## Propose

Give a user-run deployment scoped to the verified output and target. Do not erase a live directory before a replacement is ready. Preserve the prior release or atomic release switch where the existing platform supports it. A build command is separate and must honor any no-build instruction.

## Verify

Check the public hostname, main page, one asset and a nested route after deployment. Confirm the intended release content and TLS. Upload success does not prove routing or cache behavior. Hand source and build-configuration repairs to CortexCode.

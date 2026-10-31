Edit Nginx directives in the correct server/location scope and validate includes before reload.

Locate the configuration used by the running Nginx instance and its installed version. Package, Homebrew and container paths differ. Read relevant includes; protect secrets when inspecting expanded configuration.

Inspect with format `nginx`. Identify whether the directive belongs in `http`, `server`, `location` or an upstream block. Ordering and inheritance matter. A matching word inside a commented example is not the active setting.

Preview one unique block with its inspect hash. The helper checks the replacement and revision, not Nginx semantics. A valid-looking brace structure is insufficient.

Offer the observed binary's `nginx -t` with the correct prefix/config options and permissions. It checks syntax and attempts to open referenced files. For a staged candidate, keep the same include paths and context. Do not reload after a failed check.

After the person applies and the complete config passes, offer a graceful reload through the actual service manager. Check the intended hostname, route and upstream response, then read recent errors. Keep the previous config for recovery.

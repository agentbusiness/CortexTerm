Edit TOML tables, keys, arrays or types without changing the wrong section.

Use `config` inspect with format `toml`. Read the enclosing table, not just the matching key. `[server] port` and `[client] port` are different settings. Dotted keys and `[[items]]` arrays also define scope.

Keep values typed: `enabled = true`, `port = 8080`, `name = "web"`. Do not turn a number into a quoted string unless the product requires it. Preserve multiline strings and comments.

Preview one unique replacement with the inspect hash. For example, replace `[server]` plus its current port line, leaving another table's port unchanged. Do not append a second copy of a key.

The helper uses Python's TOML parser. When it reports parser unavailable, use an installed product validator or the editor; do not claim validation passed. A parsed candidate can still contain unsupported product keys.

After the person applies, run that product's check, reload only when needed, and read the effective value. Keep the private backup until the intended behavior is confirmed.

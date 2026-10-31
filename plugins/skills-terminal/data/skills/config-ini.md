Edit INI sections and keys while respecting the application’s dialect and duplicate-key rules.

Inspect with format `ini` when the product uses ordinary section-based INI. For a different `.conf` dialect, select that product's skill and use format `text` instead.

Read the full section. `[client] timeout` differs from `[server] timeout`. Products disagree about key case, inline comments, repeated keys, valueless keys and interpolation. Preserve the existing dialect.

Preview one exact section/key block with the inspect hash. Do not append another section or key to override a value unless the product documents that behavior. Avoid broad substitutions in commented examples.

The helper's strict INI parser checks section syntax and duplicates with interpolation disabled. It is not every application's parser. If a valid product file uses unsupported syntax, use its validator and editor; do not rewrite the file to satisfy the generic parser.

After user apply, validate with the consuming product, reload if required and inspect its effective setting. Keep the private backup until verification succeeds.

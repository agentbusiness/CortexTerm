Edit JSON with comments or trailing commas while preserving the application’s JSONC dialect.

Establish the consuming product first. Inspect `.jsonc` with format `jsonc`. Some products keep JSONC in `.json` files; use their native editor and validator for those files. The helper keeps `.json` strict and refuses to widen its parser.

The helper accepts JSON strings and values, line/block comments and trailing commas. It does not accept JSON5 features such as single-quoted strings, bare keys or expressions. Preserve comments that explain a setting.

Read the enclosing object, then preview one unique block with the inspect hash. A comma belongs between members; removing the final member may require removing its preceding comma too. Keep paths and regular expressions correctly escaped.

The helper checks its documented JSONC subset. The product may use a stricter parser, a schema or different comment rules. Run that product's own check before reload.

Secrets use the editor. After the person applies, inspect the saved section and confirm the application uses the intended setting. Keep the backup until that check succeeds.

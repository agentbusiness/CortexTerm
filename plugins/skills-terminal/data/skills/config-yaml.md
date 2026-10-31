Edit YAML indentation, sequences, mappings or multiline values and check the product schema.

Inspect with format `yaml` and read the whole affected mapping or list item. Spaces define structure. Preserve the existing indentation; tabs are not indentation.

A mapping uses `key: value`; a sequence item begins with `-`. A value containing `:` or `#` may need quotes. Preserve `|` and `>` block-string indentation. Anchors, aliases and merge keys need their complete surrounding structure.

Preview an exact block with the inspect hash. Do not make a blind global substitution or append duplicate keys. The helper rejects duplicate mapping keys. Some advanced merge-key documents require the product's own validator instead.

YAML parsing needs an already installed PyYAML. Unavailable means unvalidated, not invalid and not successful. Do not install a parser automatically. Parsing does not check a Compose, Kubernetes, Cassandra or other product schema.

Run the installed product's validation on all included files before reload or deployment. For remote network configuration, preserve an independent access path and use the platform's trial/rollback mechanism. Verify both connectivity and the saved configuration.

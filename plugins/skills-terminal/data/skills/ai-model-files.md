Inspect model downloads, caches, incomplete files and disk use without deleting active models.

## Inspect

Identify the owning runtime, model holder and actual storage path. Cortex apps use their shared models folder; do not create another copy or move active weights automatically. Inspect relevant file sizes, free space, active process references and the runtime's model listing.

A partial download, a cache entry and a loaded model are different. Some formats use several shards, manifests or tokenizer files; one large file may not be the whole model. Distinguish disk size from runtime memory. Check the selected release's official checksums or artifact metadata when integrity matters.

## Propose

Downloads, moves, cache removal and model deletion are user-run actions. List exact candidates and what would need downloading again. Do not remove the active model, an only recovery copy or an unfamiliar file merely because it is large. Respect limited network access and disk space.

## Verify

Check artifact completeness and that the owning runtime can find the intended model after the person's change. File presence or a matching name alone does not prove the model loads. Do not load a second runtime to validate a cache while a model holder is active.

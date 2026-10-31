Redis or Valkey memory growth, evictions, slow commands, connection pressure or cache misses.

## Inspect

Confirm product/version and observation time. Inspect bounded sections: `INFO memory`, `INFO stats`, `INFO clients` and relevant key metadata. Compare used memory, allocator/RSS behavior, evictions, rejected connections and workload. Do not dump cached values or unfiltered slow-log arguments; they can hold credentials or private data.

## Interpret

High resident memory is not the same as live key bytes. A cache with no expiry, very large values, client buffers or persistence work can cause different symptoms. Check the actual `maxmemory` and eviction policy if permitted, returning only those named settings. Do not assume all deployments use Redis as a disposable cache.

## Change and verify

Changing memory limits, eviction policy, TTLs or deleting keys is a user-run change. State which data or requests may be lost. Do not suggest `FLUSHALL`, `FLUSHDB` or restart as routine cleanup. Sample a narrowly selected structure before designing retention changes. Afterward compare the same memory/eviction metrics and application error rate under representative load. A lower memory figure alone does not prove correct behavior.

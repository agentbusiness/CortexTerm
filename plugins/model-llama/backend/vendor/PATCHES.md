# Local llama.cpp patches

The Cortex engines and CortexTerm's model-llama run the same llama.cpp: the source in `REVISION`
(unslothai/llama.cpp `b11876-mix-ec42614`, commit `468ad58`, a 0.7.0 development build), with the
same patched `tools/server/server-context.cpp` and the same server settings for an office model
(cortex-network: a model lent under a tag answers the same whichever app serves it). This file is
the same in both apps; a change to it, or to `server-context.cpp`, is made in both.

Moved from v0.6.0 (`d8123504`) on 2026-11-04. Five patches applied at v0.6.0; upstream now does the
first itself (`get_available_slot` returns a pinned slot that is still processing untouched, so the
caller defers the task), so four remain. The surrounding upstream code at each site is unchanged in
substance at `468ad58`; every site is marked `GlobalCortex patch`.

- `create_checkpoint`: the spacing eviction (`--checkpoint-min-step`) never erases the newest
  checkpoint left by an earlier task. A caller that primes a shared history and then sends the call
  that extends it (and the next call extends that same history again) resumes exactly there.
  Upstream erased the prime's checkpoint as soon as the call created its own, whenever it lay within
  min-step of an older one, so on sliding-window (Gemma 4) and recurrent caches every later call
  resumed from the older checkpoint and re-processed up to min-step tokens. Measured in GlobalCortex
  (chat suite, Gemma 4 E4B, 2026-10-13): a full-controller turn re-read 120 to 2,060 tokens on each
  of 34 steps. Upstream runs this eviction only when the checkpoint list is full; the patch applies
  to that case.

Prompt-cache changes from CortexCode's retired llama.cpp plugin (its patches 3-5, written against
b11623, archived in CortexCode commit `82562e6`). They matter where requests are pinned to a slot
(`id_slot`) or the KV pool is unified (`--kv-unified`).

- `get_available_slot`: an empty slot pinned by id loads the best matching prompt from the host-RAM
  prompt cache. Upstream computes the kept fraction as `0/0` (NaN) for an empty slot, so the cache
  was never searched and a conversation displaced to RAM was processed from scratch when it came
  back on another slot. (CortexCode patch 3.)
- `try_clear_idle_slots`: with a unified KV pool, a request that does not fit purges idle slots;
  upstream discarded their state. The purged slot is saved to the host-RAM prompt cache first (when
  one is configured), so its conversation resumes from RAM. (CortexCode patch 4.)
- `get_available_slot`: the fraction of a slot that is kept is what can actually be resumed.
  Upstream keeps a slot in place (instead of moving it to the RAM prompt cache) whenever the longest
  common prefix with the new prompt covers half of it; with recurrent, hybrid or sliding-window
  memory a common prefix is only resumable up to a context checkpoint (or within the rollback window
  for recurrent state), so two conversations sharing a long block made upstream keep the old one,
  process the new prompt from scratch anyway and lose the old conversation. The patch counts only
  the resumable prefix; under half, the old conversation goes to the prompt cache and the best
  cached prompt is loaded. Memory that can remove any suffix (`COMMON_CONTEXT_SEQ_RM_TYPE_PART` with
  no sliding window) keeps upstream's rule. (CortexCode patch 5.)

CortexCode's patch 6 (`--spec-max-parallel`) was not ported.

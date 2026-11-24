# Security triage cards

One card per finding type; the file name is the card id, `general.md` the fallback. A small local
model (Gemma 4 E2B/E4B, thinking off, or Qwen) reads the card, then numbered facts: area, rule,
severity, count, what, signer, notarized, path_class, seen_days, quarantine_from, running, parent,
precedent.

A card is plain text under about 170 words: one sentence on the finding, "Questions:" (3 to 5,
each a snake_case id with "Yes when" naming facts), one line per outcome, and a last line with the
base rate and the strongest red sign, since a small model follows the nearest cue. The model
answers yes, no or unknown, then picks one outcome:

- normal: real and fine here; resolved and hidden.
- fix: upkeep; the action names the exact step.
- threat: an attack or real risk; the action is the first safe step.
- unsure: the facts do not answer; read-only checks follow.

Hard evidence is always threat. No card trusts a name alone. Every card change is tried on both
Gemma and Qwen in the real app before it lands.

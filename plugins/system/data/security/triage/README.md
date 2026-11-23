# Security triage cards

One card per finding type. A small local model (Gemma 4 E2B/E4B, thinking off, or Qwen) reads the card
for a finding plus facts computed by code, and returns one verdict in about a second.

Facts (lines F1..Fn): area, rule, severity, count, what (untrusted text), signer, notarized, path_class,
seen_days, quarantine_from, reputation, running, parent, precedent. Cards name facts only by these names.

Verdicts: expected (real and normal here), false_alarm (the check is wrong here), escalate (needs a
deeper look or the person), plus similar yes/no (the verdict holds for other findings with the same rule
and signer). A benign verdict must cite the fact ids that support it; code rejects one that does not.
Hard evidence (malware match, known-bad hash or address, exploited CVE, malicious package, campaign
leftover, malicious extension) is never lowered by the model; those cards only guide the explanation.

Format: plain Markdown, about 120 to 170 words, short lines, no tables, simple English.
Line 1 is a one-sentence summary used as the title. Then Means, Normal when (3 bullets),
Suspicious when (3 bullets), Never decide from, Precedent, and last "When unsure: escalate."
The strongest rule goes last, because a small model follows the nearest cue.
Every bullet names the facts that decide it; no card tells the model to trust a name.

The cards are written in the project's own words. Public detection rules were read for accuracy only.
File name = card id + `.md`. `general.md` is the fallback.

Every change to a card must be tried on both Gemma and Qwen in the real app before it lands.

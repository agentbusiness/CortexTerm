# Terminal flow 0.1.15: task skills and configuration previews

The foreground flow now shortlists compact task cards, attaches a clear match, separates skill lookups from read-only checks and counts the templated context before generation. A configuration tool inspects files and prepares user-run, hash-bound changes. It never applies a change. The 0.1.15 work is source-only: no build, package install, app launch or live model validation. See [the complete loading/configuration description](../../docs/terminal-skills/README.md) and [100-workflow coverage](../../docs/terminal-skills/COVERAGE.md). Existing learning and recall behavior is described below.

# Terminal flow 0.1.14: learning and recall

CortexTerm learns inside its own chat-flow plugin and its own IronGraph. It does not read
CortexCode's memory. This adds no shared protocol, plugin architecture or model-sharing change.

## The loop

On activation, after a turn, and after a command finishes, an idle worker takes up completed
terminal turns. It reads the real session journal, the facts and checks shown to the model, the
answer, any command proposal, the next explicit user correction, and the actual proposed-command
outcome. Proposal bindings are journaled; if the plugin missed an event during a restart, the
first command in that shell after the proposal can be recovered from command history (within
10 minutes and before the next manual request).

The learner extracts one short, evidence-backed lesson from a demonstrated command correction,
a failed check followed by a successful check of the same command family, or an explicit user
correction. A proposal that was never run is not a successful fix. A successful helper command
for another program is not proof of a fix. Both Gemma and Qwen receive the same constrained
JSON form and prompt. Learning uses the existing shared model, background priority and idle-only
scheduling. A foreground turn cancels background work; each model lease is released on exit.

Before answers, explanations and fixes, the flow recalls live facts for the current folder and
its ancestors, relevant lessons by meaning, and lessons with the same failure key. It also adds
matching lessons immediately after a failed check. Facts and lessons are observations; current
evidence, the user's request and the risk engine retain authority. Local lessons are scoped to
their folder and descendants; general lessons are scoped to the platform. Suspicious memory is
excluded. If memory is unavailable, the answer can proceed without it.

## Persistence and feedback

All durable learning state uses `memory@1` in CT's main graph:

| Record | Connections and contents |
| --- | --- |
| `TerminalEpisode` | `OF` Session, `ABOUT` Folder, `SHOWN` Knowledge, `OBSERVED` CommandRun; actual request snapshot, checks, answer, proposal and outcome |
| `TerminalLearningPass` | `FROM` episode; extracted lesson and completion checkpoint per evidence revision |
| `Knowledge:Lesson` | `LEARNED_FROM` episode, `ABOUT` Folder for local lessons; text, scope, failure aliases and journal evidence |
| `TerminalFeedback` | `FOR` lesson, `FROM` episode; verdict, observation source and evidence |
| `TerminalReplay` / `TerminalNightReport` | replay `FOR` lesson and `FROM` episode; daily review `ON` Machine |

The request snapshot is the actual model message payload, stored as JSON text; the episode,
lessons, outcomes and feedback remain separate related graph records. Session journals remain
journal files, as the app's graph model specifies. No learning database, report files or replay
working directories are introduced.

Stable observation keys make feedback idempotent across retries. CT derives its scores from
feedback records rather than incrementing the generic knowledge counters. A sole matching lesson
can be credited when the proposed command is actually run successfully for that failing command
family, or a matching failed check is corrected. Several matching lessons are recorded as
confounded. A repeated matching failure or an explicit user correction can count against a shown
lesson. Unrun proposals and completed prose get no success credit. Lessons with more harmful
than helpful observations after at least three decisive observations are withdrawn. Withdrawn
items remain history; recall excludes them and an upsert does not revive them.

## Recorded-context replay and daily review

At idle, after the backlog, a candidate lesson is tried in two answer-only generations using the
same recorded evidence, with and without that lesson. The model identity must match in both
arms. An actual successful command of the same failing command family supplies an exact-match
oracle: one arm proposes that recorded command and the other does not. Equivalent commands
that differ in text are not credited. Empty, unfinished or mismatched-model generations decide
nothing. Both actual answers, their model identities, oracle and verdict are kept in the graph;
interrupted comparisons resume from saved arms. Replay output never feeds the learner.

This measures proposal recall in recorded context. It does not execute commands or demonstrate
that a repair would work again on a live machine. Answers without an observed successful command
are not graded by the model itself. User corrections still teach and score lessons for answers.

Once per UTC day, the worker writes a graph review of scores, replay evidence and proposed skill
additions (at least three helpful observations and no harm), plus possible host repairs (at
least five helpful observations, no harm, and a failure key). These are review proposals; learning
never edits skills, application code or risk policy.

## Verification for this change

The requested implementation is source-only: no build, package, install, application restart,
repository test suite or benchmark was run. Rust parsing, JSON/TOML validation, patch whitespace
and read-only Cypher checks are recorded in `docs/learning/GATES.md`. Compilation, live behavior,
Gemma/Qwen generations, foreground preemption, restart recovery and use on an 8 GB Mac require
validation after an authorized build. These are not established by source inspection.

## Streaming command checks — unreleased source changes

Read-only shell checks publish sanitized stdout/stderr while running, at most once every 150 ms,
in the existing `command_step.output` journal field. The same final text is shown to the person
and returned to the model, with the existing 200-line limit and a 128 KiB combined capture bound;
the pipes continue draining after the bound. Stdout precedes stderr as before. Cancellation and
the 20-second deadline terminate the process group and retain output already captured. No model
prompt or tool contract changes. The UI uses the same 320px scroll area as shell Runs.
Source inspection is complete; building and live streaming verification remain unperformed.

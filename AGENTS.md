# CortexTerm: notes for anyone working on this repository

CortexTerm is an AI-native graphical terminal. Every shell command works; the same input takes plain
language; every command becomes a Run you can search, chart and explain. It is a local-model app: Gemma 4
(tag `office`) on its own, or the machine's shared Qwen (tag `coding`). Its chat flow is `terminal`.
Plan: `docs/PLAN.md`. Feature inventory: `docs/FEATURE-INVENTORY.md`.

## Keep it simple

Pick the simplest design that does the job. Don't add sharing, sync, layers or options that nobody asked
for. When a plan grows a second mechanism for the same thing, drop one of them.

## The shared standard (CortexCode and CortexTerm)

CortexTerm is a separate app with its own frame, plugins, home (`~/.cortexterm`), releases and memory.
Its code was copied from CortexCode (`../CortexCode`) and reshaped. Both apps follow the same standard:

- the plugin package: `plugin.toml` (`ccplugin/1`), `.ccplugin`, hello and lifecycle;
- CPP/1 and routing by method prefix;
- the wire shape of every contract both apps have (`model@1`, `mesh@1`, `notify@1`, `skills@1`,
  `terminal@1`, `chatflow@1`);
- the mesh: ALPNs, pairing, membership log, card, claims, lending, `mesh.link`, `mesh.session.start`;
- model and resource sharing: model tags (`coding`, `office`), one model per machine, the yield
  handshake, one models folder for every Cortex app (`~/.cortex-models`, `docs/SHARED-MODELS.md`;
  `shared-models/`);
- shared services (`protocol/src/contracts/service.rs`): the verbs and what each may do, the
  `<category>.shares` declaration, where a call may come from, the caller, run options, jobs and
  read sizes, and the one-tool-per-service builder;
- the write sandbox, `sandbox-kit/`, and the shared models folder, `shared-models/`: the same code
  in both repositories, byte for byte.

**Any change to the plugin architecture, the mesh, or model and resource sharing is made in both
CortexTerm and CortexCode**, in the same piece of work, and listed in both repositories' docs with the
version it lands in. A change to anything outside the standard stays in its own app.

## Models

- One model per machine. Before loading a model, look for a running one on this machine and borrow it.
  CortexTerm accepts Gemma or Qwen; CortexCode needs Qwen. When CortexCode needs Qwen next to a running
  Gemma, the Gemma holder yields after its current turn.
- Memory tiers: Gemma 4 E4B above 8 GB, Gemma 4 E2B on 8 GB Macs.
- Every prompt, stage, schema, skill and tool text must work on both Gemma and Qwen. Try each change on
  both. CortexCode's lens applies: a small model follows the nearest strong cue at the moment it decides.
- The model explains; it never decides whether a command runs. That decision is the risk engine's (code).

## Memory and remote work

- CortexTerm has one global memory of its own (places, Runs, hosts, habits, fixes). It is never shared,
  and CortexTerm never reads CortexCode's memory.
- Coding work is handed to the CortexCode on the machine where the repository lives, if there is one.
- Remote terminals and Desks run on the target machine through the CortexTerm runner. They execute
  there and use that machine's memory.

## The mockups are the reference

The design canvas (https://claude.ai/artifact/SYWUQrGkcii1eEzrYbQwJy) shows how every screen must look
and behave. A UI change is done only when the running app matches its board: layout, type, colours,
labels and the keys shown on buttons. Check by screenshotting the running app next to the board. If the
build should differ from the board, change the board on purpose and say why.

## Checking a change

As in CortexCode: no test suites, check scripts or benchmark folders in the repository. Check a change by
using the real app on a real machine, including an 8 GB Mac. When the model does the wrong thing, read
the session journal before changing anything.

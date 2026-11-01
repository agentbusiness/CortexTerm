# Cleanup — 0.1.0

Disk space a computer can get back, in the CLEANUP tab of Workbench's right pane (local and mesh
computers). One plugin owns the scan, the checks, the cleaning and the UI (`cleanup@1`,
`protocol/src/contracts/cleanup.rs`).

## What it finds

| Kind | How it is recognised |
| --- | --- |
| build | a project's output beside its marker: `target` + `Cargo.toml`, `node_modules` + `package.json`, `.next`, `.build` + `Package.swift`, Gradle, Maven, .NET, Python caches and venvs, Zig, Dart, Terraform, Pods; Xcode DerivedData mapped to its project through `info.plist` |
| cache | package and tool caches (cargo, npm, pnpm, yarn, bun, go, pip/uv/poetry, conda, Gradle, Maven, Homebrew, CocoaPods, device support, simulators, IDEs), and any folder carrying a `CACHEDIR.TAG` |
| agent | agent worktrees (`.claude/worktrees/*`), agent scratch and logs, old transcripts, Cursor's state backup, aider caches |
| temp | old files in `$TMPDIR`, old logs, installer images in Downloads |
| model | Hugging Face and LM Studio downloads (review only) |
| stale | a folder of 2 GB or more, 2–4 levels below home, that nothing changed in for 180 days and no recipe knows |
| duplicate | files of 64 MB or more kept twice (same volume and size, then BLAKE3 of both ends, then of the whole file; hard links count once; copies that are already APFS clones are not offered) |
| trash | the Trash |

The recipes are data (`data/recipes.toml`, read from the live folder when present), so a new kind
of junk is a few lines, no build.

## What keeps a find safe

- **In use.** One snapshot of this user's processes with their working folders and open files
  (`proc_pidfdinfo` on macOS, `/proc` on Linux) per scan, and another just before cleaning. A
  build lock a running tool holds (cargo's `.cargo-lock`, tested with a non-blocking `flock`), a
  recipe's program working in the project, or a recipe's app being open marks it in use.
- **Only the old builds of a project in use.** A project changed, built or used in CortexTerm
  (its CommandRuns in the graph) within 14 days keeps its build: for Rust only the parts cargo
  will not use again are offered, worked out again just before cleaning — a profile not built
  for 30 days while another was, older hashes of a unit in `deps`, `build`, `.fingerprint` and
  `incremental`, and rustc's older incremental sessions.
- **Warm.** A whole item changed in the last two days is offered but never cleaned by the AI.
- **Git.** Nothing git tracks is cleaned; ambiguous build folders (`dist`, `build`, `bin`…) must
  be ignored by git; an agent worktree with uncommitted work or commits on no branch stays and is
  removed with `git worktree remove`, so its branch stays.
- **Places never touched**, whatever a recipe or the model says: keys and credentials, Mail,
  Messages, Photos, iCloud and cloud storage, device backups, CortexTerm's and CortexCode's homes
  and the shared models folder. Only files of this user in the home and temporary folders; never
  a symbolic link.
- **How it goes.** Regenerable things are deleted; the person's files (review) go to the Trash;
  a tool with its own clean command gets it (`brew cleanup`, `go clean -modcache`, `npm cache
  clean`, `pnpm store prune`, `hf cache rm`); duplicates become APFS clones of one copy, so every
  path keeps its file. Emptying the Trash and moving review items asks twice in the UI.

## Decisions and the AI

Per find: **CLEAN**, **KEEP** (intended: never offered and its folder never read again, which is
what saves scanning time), **NOT NOW** (30 days) and **WHAT IS IT?** (the local model explains it
from measured facts). **LOOK AGAIN** undoes a keep or a postponement.

**CLEAN UP WITH AI** asks the local model (Gemma or Qwen, a JSON-schema answer, 30 items per call)
for a plan over the open finds, with the person's 25 latest decisions from the graph as context.
The plan is shown first. The model chooses; the plugin's rule decides what it may do: it cleans
only regenerable, idle finds; keep and not-now are always allowed; everything else is shown as
"yours to decide". Applying records each step with `by: ai` and its reason.

## The graph

Every scan, find, decision and clean is in the terminal's graph (docs/GRAPH-MODEL.md, "Disk
cleanup"): `CleanupScan`, `Reclaimable` (with `bytes` and `status` histories) linked to its
`CleanupRecipe`, its folder, its project, the `Program`s using it and its duplicate `LargeFile`s;
`CleanupDecision` (verdict history) about it; `CleanupAction` for each clean, and the
`cleanup.actions` stream. Nothing is written to files.

## Scanning

A parallel walk (rayon, at utility priority on macOS) of the home folder on its own volume,
counting bytes on disk (allocated blocks), never following links, skipping `~/Library` (its known
places are read by recipe), `.git` folders and app libraries. A recognised folder is measured
whole and not looked into further. Progress is published as `cleanup.progress`.

## Verification

Source only (`cargo check`, `tsc --noEmit`); not built, packaged or installed. The scan code was
run read-only against a real home folder from a scratch harness. Not yet checked: the tab in the
running app next to a board (the design canvas has no Cleanup board yet), cleaning on a real
machine, an 8 GB Mac, and the plan on both Gemma and Qwen.

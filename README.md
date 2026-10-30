# CortexTerm

**An AI-native graphical terminal that runs on your own machine.** Every shell command works. The same
input takes plain language. Every command becomes a Run you can search, chart and explain.

CortexTerm is CortexCode's sibling. It has its own frame and plugins, built to the same standard:
the plugin format, the contracts, the mesh and model sharing (see `AGENTS.md`).

## What it does

- **The Line.** One input for shell commands and questions. Before you press Enter it says what the
  input is (SHELL / ASK), which program runs, where, what its globs match and how risky it is. The
  risk engine is code, not the model. Tab completes and → takes the history suggestion.
- **Stage and Shelf.** A Desk holds one job's panes. The Stage shows the one to three you work in, and
  the Shelf shows the rest as live cards. ⌘J brings whatever needs you onto the Stage. ⌘M opens the
  Map of every Desk, and ⌘; jumps to a pane by name, command or folder.
- **Runs.** The shell integration (injected automatically for zsh, bash and fish) records each
  command's folder, exit code, duration and output. A Run opens as a log view with a timeline
  histogram, levels and filters.
- **Native views.** `nano` / `vi` open a fast editor, `top` / `htop` open the process view. A
  leading `!` runs the real program.
- **The machine.** The right sidebar shows CPU, memory, GPU, network, disk and the model, read
  without sudo. Below that is the process list with ports and actions, and every row is
  explainable. Watchers post the obvious (runaway CPU, memory climb, disk full, new open port, new
  login item). A daily security sweep checks for vulnerable or outdated tools, SSH key hygiene and
  secrets in shell history.
- **Local AI.** It runs Gemma 4 (E4B above 8 GB, E2B on 8 GB Macs) on llama.cpp. There is one model
  per machine: when CortexCode runs, CortexTerm borrows its model instead of loading its own.

## Start

```sh
./cortexterm
```

The first start builds the app into `build/` and installs its plugins into `~/.cortexterm`.

## Requirements

A Mac with Apple silicon and 8 GB of memory or more.

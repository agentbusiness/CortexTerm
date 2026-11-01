# @cortex-ui/memory-irongraph-settings-memory

Settings › Memory: what CortexTerm remembers in its global memory. The terminal flow's lessons,
with why each is kept (a fix that worked, a check that worked, your correction, something you
said) and how it fared (helped · hurt · shown); the folders' habits; and what was set aside.
**Why** opens the episodes a lesson was learned from and its held-out replays (graph reads).
**Forget** withdraws a lesson as yours, so the learner does not learn it again.

- **Plugin id:** `memory-irongraph.settings-memory`
- **Slot:** `settings.memory@1`
- **Build:** `npm run build` → `dist/` (`index.js`, `style.css`, `manifest.json`)
- **Reads:** `memory.knowledge.list`, `memory.graph.query`, `frame.project.list` (the home folder, for `~`)
- **Writes:** `memory.knowledge.withdraw`

React, ReactDOM and `@cortex/sdk` are peer dependencies the workbench provides. The board is
"Settings › Memory" on the design canvas.

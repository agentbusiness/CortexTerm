# File Browser — 0.1.0

One plugin owns the Files UI, filesystem backend and native transfer module. Workbench only hosts
`machine.files@1` in the existing right-side pane, alongside Machine, Alerts, Traces, SSH and
Schedules, when a remote mesh computer is selected and this plugin's UI is enabled. Switching to
the local computer or disabling the plugin falls back to Machine. No local Files tab, shell
commands, model calls, new permission switches or mesh transport.

## Ownership and routing

| Part | Responsibility |
| --- | --- |
| `backend/` | CPP/1 `filebrowser@1`: home-rooted listing, bounded reads, upload staging and publication |
| `ui/` | `machine.files@1`: breadcrumbs, parent navigation, hidden-file toggle, selection, transfers and errors |
| `shell/` | CPP/1 `filebrowser-native@1` via the existing `load(api)` shell-module interface: native local dialogs, disk IO, progress and cancellation |

Filesystem calls use the selected computer's `ComputerScope`. Native transfer calls use the local
frame explicitly; the shell module verifies the target is a remote CortexTerm member and obtains
its authenticated tunnel through `mesh.link`. Chunk calls use the frame's existing `/api/rpc`
endpoint through that tunnel. No file paths or tokens are placed in a command line, and no model
decides whether a file operation happens. All methods are declared in hello; none are exported to
model-shell commands. `[[shell]].serves` lets the standard plugin lifecycle remove its route when
the plugin is disabled. The UI's locations and last transfer IDs use the existing slot state.

## Browsing and transfers

The root is the serving user's actual HOME, independent of project roots or the local machine.
Dotfiles are hidden initially. Folders sort first, then names. Breadcrumbs and Parent folder
navigate within home. Symlinks resolve only when their targets remain inside home; reads and upload
destinations walk directory descriptors without following swapped path components. Unavailable,
special or non-UTF-8 names remain visible but disabled. Filesystem permission errors are reported
without changing permissions or escalating privileges.

Upload opens the local file picker and sends the selected regular files sequentially into the
remote folder captured when Upload was clicked. Download saves the selected remote file through
the local native Save dialog. Both use 256 KiB chunks and bounded memory; file content never enters
the renderer or the memory graph. Progress and cancellation remain available after tab switches.
Download snapshots detect source changes; local uploads detect changes to the selected source.

Uploads stage hidden mode-0600 files in the destination folder and publish complete files with
`linkat`, refusing existing names even if they appear during transfer. Rename a conflicting local
file before uploading it. Local downloads stage beside the chosen destination; replacing an
existing file requires the native Save dialog's confirmation and an unchanged destination stamp.
Completed files stay complete when a later file fails or a multi-file upload is cancelled.

Cancellation, failure, plugin shutdown and five minutes of upload inactivity clean up partial
uploads. Local partial downloads are removed on cancellation, failure and module unload. A hard
process crash can leave hidden `.cortex-upload-*` or `.cortex-download-*` byte files; they are never
treated as completed files or automatically resumed. No durable transfer metadata is stored in
sidecar files. A new transfer is required after a disconnect.

## Design and verification

The tab reuses Workbench's existing tab styling. The plugin uses the current theme's ground, ink,
rules, rubric and counter colours, Archivo controls, Source Serif body copy and monospaced paths;
it does not introduce a separate visual system. The supplied machine-tab screenshot and existing
machine-pane source are the available references; the official Claude canvas required sign-in.

This change is source-only at the user's request: no build, package installation, app restart or
live mesh transfer has been performed. Visual agreement with the official board and real-machine
behaviour (including an 8 GB Mac) remain to be checked in a separately authorized build/run.

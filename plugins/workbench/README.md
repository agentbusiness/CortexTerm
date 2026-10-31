# Workbench (`workbench`)

The window (`window@1`: the page the frame serves at `/ui/`, with the slot engine that loads every plugin's UI packages, the workbench layout, the start-up splash, and React and `@cortex/sdk` for every plugin through its import map; a new version reloads open windows), the workbench's right pane host (`workbench.rightPane@1`: one view at a time from every `pane.<name>@1` plugin, as tabs) the brand band's connection mark (`workbench.band@1`: nothing while connected; "Connecting to the frame" or "Frame unreachable" in rubric otherwise), and Settings > Appearance (`settings.appearance@1`: the ground, Plate, Auto or Page).

One self-contained plugin folder, separable into its own repository (only `cc-protocol` and `@cortex/sdk` come from outside):

| Path | What |
|---|---|
| `plugin.toml` | identity, build commands and outputs, UI packages and their slots, shell modules, source location |
| `ui/` | one npm workspace (own `package-lock.json`, `@cortex/sdk` as a local dependency): `ui/band-connection` (workbench.band@1), `ui/right-pane` (workbench.rightPane@1), `ui/settings-appearance` (settings.appearance@1), `ui/window` (window@1; its `build.mjs` builds the SDK from source and puts it beside React in `dist/vendor/`); each package builds `dist/` with `manifest.json` |

## Build and run

```sh
cd ui && npm ci && npm run build && npm test     # after the SDK is built (cd ../../ui/sdk && npm run build)
cortex-pack build plugins/workbench                  # -> plugins/workbench/target/workbench-<version>-<target>.ccplugin
```

`cortex-pack build plugins/workbench --install` packs the folder into a `.ccplugin` that the frame installs (`frame.plugins.install`), which hot-swaps the UI packages together; Settings > Plugins disables and enables the whole plugin.

## Command output — unreleased source changes (0.1.20)

Command output, assistant checks, and in-card tables/logs have a 320px maximum body height.
Output follows its latest line until the reader scrolls upward, uses an upward navigation key,
or starts selecting text. “Follow output ↓” resumes the live tail. Paused Run cards hold a fixed
400-line window; “earlier lines” pages backward through the recorded output. Completion does not
shrink the card to a different line count. Temporarily showing the terminal preserves the block
stream and its reading positions.

The existing xterm instance supplies live progress: explicit OSC 9;4 reports take precedence;
otherwise an actual redraw of the same row must confirm a recognizable bar/counter or a changing
spinner glyph. Ordinary numbered lines are never merged. Up to four active inferred bars appear
above the output, using the program's percentage or an indeterminate indicator. A phase reaching
100% does not finish the Run: its shell exit decides the outcome. Progress clears at the next Run
and never changes the recorded output. Ambiguous text stays text. No command-name adapters,
injected command flags, additional emulator, dependency, or shared protocol changes are needed.

The window respects `TermState.interactive` as well as alternate-screen mode for direct keyboard
ownership, retaining the manual terminal toggle, the existing input forms and paste guard.
This source change has not been built, packaged, installed, or visually verified in the app.

# Mac security skills (`skills-mac-security`)

Security know-how for CortexTerm's model as one `skills@1` plugin (the `skills` family), macOS
only: `security-check`, `security-explain`, `cve-check` and `security-incident`. Terminal flow 0.1.15 shortlists relevant summaries and attaches a clear match; the model can read another with `skill`. The skills
send the model to one script, `macsec`, which runs the system plugin's checks; the code finds, the
model explains what the check printed and never gives an all-clear of its own.

One self-contained plugin folder, separable into its own repository (only `cc-protocol` and
`cc-lang-kit` come from outside):

| Path | What |
|---|---|
| `plugin.toml` | identity, build command and output, `data/` as the plugin's data |
| `backend/` | Cargo workspace (depends on `cc-lang-kit` by path), binary `cc-skills-mac-security`: category `skills-mac-security`, contract `skills@1`, served by `cc_lang_kit::run_skills_plugin` |
| `data/skills/` | the skills (`<name>.md`: line 1 the one-sentence summary of when to read it, a blank line, the Markdown body) |
| `data/scripts/macsec` | the command the model runs; the chat flow answers it inside the app (run in a shell, it only says where to ask) |
| `data/scripts/readonly` | the subcommands of each script that only read: `macsec check cve areas help` |
| `data/knowledge/security.md` | the security notes: one short plain note per rule, finding source or built-in, with the ATT&CK ids that apply |

## What it serves

Methods are called on the category: `skills-mac-security.describe` (id, name and every skill's
name and summary) and `skills-mac-security.skill` (`{name}` -> `{name, text}`, the whole file).

## `macsec`

The model runs it by its full path, `~/.cortexterm/live/plugins/skills-mac-security/data/scripts/macsec`.
The terminal's chat flow does not start a shell for it. It hands the words to the system plugin
(`system.ask`), which answers inside the app, with this folder's `data/knowledge/security.md` notes
for the findings:

- `macsec check <area>...`: the system plugin's checks (settings, updates, apps, packages, malware,
  persistence, privacy, intrusion, network, agents, ssh, secrets, all), within 15 s. An area that
  does not fit reports the last daily sweep; `--full` waits for every area.
- `macsec cve <ID>`: whether this Mac is affected by a CVE or GHSA, with CVSS, CISA KEV and EPSS.
- `macsec areas`, `macsec help`.

Filesystem discovery starts at the user's home folder, then continues from `/` through other
users' folders, system folders and mounted volumes. Hidden/nested projects and directory symlink
targets are included; directory identity prevents loops and duplicate traversal. Apps, project
lockfiles/venvs, `.env` files, agent configs/instructions/skills and persistence checks use this
discovery. Malware checks stream regular files in the same home-first order, without the old
age, depth, file-count, file-size or total-scan-time cutoffs. A YARA file still has a 5 s timeout;
errors name the file. Devices/process pseudo-filesystems and the scanner's own records/rules are
excluded, and inaccessible locations are reported under `Not checked`.

A full sweep waits for filesystem discovery and project dependency lookups. Short chat checks
retain their explicit deadline and report cached/missing areas; cancellation stops their filesystem
walks. Use `macsec check all --full` inside CortexTerm for a fresh full check. Discovery does not
grant access: protected files still need the operating system's permissions. Dependency files over
30 MiB and agent text files over 8 MiB remain explicitly reported as not checked. All Docker
images are attempted, and all Sparkle app feeds are queried in batches of at most 20.

Every fix the checks print is offered, never run.

The terminal's risk engine (`plugins/terminal/backend/src/assess.rs`) lets the model run it on its
own: a program that resolves to `<home>/live/plugins/skills-<id>/data/scripts/<name>` with a
subcommand that plugin's `data/scripts/readonly` lists for `<name>` is read-only; with a `!` flag
from that line (`--full`, minutes long) it is the person's to run. Anything else about the script,
and any pipe or redirection after it, is judged as usual.

## The security notes

`data/knowledge/security.md` is the one copy: the terminal flow (`chatflow-terminal`) reads it from
the live folder when it explains a finding, alert or flagged command, and `macsec check` prints the
notes for its findings. Without this plugin, explanations go without notes.

## Build and run

```sh
cd backend && cargo build --release && cargo clippy --release --all-targets -- -D warnings
cortex-pack build plugins/skills-mac-security   # -> plugins/skills-mac-security/target/skills-mac-security-<version>-<target>.ccplugin
```

The frame runs it once installed (`cortex-pack build plugins/skills-mac-security --install`). The
probe runs `describe` (at least one skill), reads every skill back through `skill` (line 1 is the
summary `describe` gave, a body follows) and asks for an unknown skill (`not_found`).

## Skill wording 0.1.4

The four cards use compact output-grounded instructions. No-findings results name their checked scope; incomplete checks remain visible. EPSS is not the chance that this particular Mac will be compromised. Security knowledge avoids unconditional exposure or compromise claims from a setting alone. This wording change has source review only; no fresh security sweep, build or model session was run. See [terminal skill release notes](../../docs/terminal-skills/README.md).

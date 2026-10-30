//! `terminal@1`: PTY-backed terminals for the UI (and readable by agents via screen snapshots).

use serde::{Deserialize, Serialize};

pub mod methods {
    /// [`OpenParams`] -> [`TermInfo`]. Runs the shell as a login shell (`-l`) on a new PTY.
    pub const OPEN: &str = "terminal.open";
    /// Write user input (UTF-8 text, may contain control characters).
    pub const WRITE: &str = "terminal.write";
    /// [`ResizeParams`] -> [`TermInfo`]: sets the PTY window size (the shell receives SIGWINCH).
    pub const RESIZE: &str = "terminal.resize";
    /// [`TermParams`] -> [`TermInfo`]: SIGHUP to the shell's and the foreground process groups,
    /// then SIGKILL if they do not exit; the terminal is removed from the list.
    pub const CLOSE: &str = "terminal.close";
    pub const LIST: &str = "terminal.list";
    /// Current screen as plain text (parsed by a VT emulator), for agents and tests.
    pub const SNAPSHOT: &str = "terminal.snapshot";
    /// [`StateParams`] -> [`TermState`]: where the shell is (folder, at a prompt or running, the
    /// last exit code, full-screen program), from the shell integration's marks.
    pub const STATE: &str = "terminal.state";
    /// [`RunsParams`] -> [`RunList`]: recorded Runs (one per command), newest first. Runs are kept
    /// in the memory plugin's graph (`CommandRun` nodes) and streams (`shell.<term_id>`,
    /// `run.<id>.output`); see `docs/GRAPH-MODEL.md`.
    pub const RUNS: &str = "terminal.runs";
    /// [`RunOutputParams`] -> [`RunOutput`]: a window of a Run's output lines (ANSI removed), with
    /// an optional filter.
    pub const RUN_OUTPUT: &str = "terminal.run.output";
    /// [`HistogramParams`] -> [`Histogram`]: a Run's output lines per time bucket and level.
    pub const RUN_HISTOGRAM: &str = "terminal.run.histogram";
    /// [`AssessParams`] -> [`Assessment`]: what typed input would do before it runs: shell command
    /// or question, the program it runs, what its globs match, and its risk.
    pub const ASSESS: &str = "terminal.assess";
    /// [`CompleteParams`] -> [`Completions`]: completion candidates at the cursor.
    pub const COMPLETE: &str = "terminal.complete";
    /// `{limit}` -> [`PlaceList`]: folders the user worked in, most used first.
    pub const PLACES: &str = "terminal.places";
    /// [`FileReadParams`] -> [`FileText`]: a text file for the native editor (`nano` and friends).
    pub const FILE_READ: &str = "terminal.file.read";
    /// [`FileWriteParams`] -> [`FileWritten`]: save it atomically (temp file, rename; mode kept).
    /// A file the user cannot write is refused with `needs_admin: true` in the error message's
    /// data, and is never written with elevated rights by this method.
    pub const FILE_WRITE: &str = "terminal.file.write";
    /// [`HabitsParams`] -> [`Habits`]: what CortexTerm learned about a folder (and the folders above
    /// it): the commands used there most, how they usually end and how long they take, and notes.
    /// Kept in the memory plugin (IronGraph), learned from Runs.
    pub const HABITS: &str = "terminal.habits";
    /// [`AskAnswerParams`] -> null: answer what the running command asks ([`TermState::ask`]): the
    /// text and a return go to the terminal; `remember` keeps a secret in the macOS Keychain under
    /// the ask's `key`, and the next time the same program asks the same thing it is filled in.
    pub const ASK_ANSWER: &str = "terminal.ask.answer";
    /// [`AskForgetParams`] -> null: remove a saved secret from the Keychain.
    pub const ASK_FORGET: &str = "terminal.ask.forget";
    /// [`ScanParams`] -> [`ScanResult`]: the paste guard alone, over any text (a pasted command, a
    /// script, the shell blocks of a skill file): the stealer and exfiltration shapes it holds,
    /// after decoding its layers, and the hidden text in it. Plain code, no network, nothing runs.
    pub const SCAN: &str = "terminal.scan";
    /// [`ScriptFetchParams`] -> [`Script`]: download the script a `curl … | sh` would run (capped,
    /// never run) and scan it, so it can be read and explained first.
    pub const SCRIPT_FETCH: &str = "terminal.script.fetch";
    /// [`ScanParams`] -> [`PackageCheck`]: the packages an install command names (npm, pnpm, yarn,
    /// bun, pip, uv, pipx, cargo, gem), looked up in OSV: known malware (`MAL-` ids) and known
    /// vulnerabilities. Empty for a command that installs nothing by name.
    pub const PACKAGES_CHECK: &str = "terminal.packages.check";
    /// [`SandboxParams`] -> [`Sandboxed`]: the command line that runs `command` in the write
    /// sandbox with no access to the person's secrets (SSH and cloud keys, keychains, browser
    /// profiles), for the person to run in their terminal. macOS only.
    pub const SANDBOX_WRAP: &str = "terminal.sandbox.wrap";

    /// `{}` -> [`crate::contracts::service::ShareList`]: the services this plugin shares
    /// (`terminal.command`).
    pub const SHARES: &str = "terminal.shares";
    // The command service (`terminal.command`): a command run for another app on this machine, in
    // the person's login shell (their PATH and setup), optionally in the write sandbox and traced.
    /// [`super::CommandRunParams`] -> [`crate::contracts::service::Job`]: run it; its output
    /// streams as items `{kind: "output", text}` and the answer comes when it ends (at once with
    /// `background`). It is a Run in CortexTerm (its id is the Run's).
    pub const COMMAND_RUN: &str = "terminal.command.run";
    /// `{id}` -> [`crate::contracts::service::Job`]: stop a running one (its whole process group).
    pub const COMMAND_STOP: &str = "terminal.command.stop";
    /// `{}` -> `{jobs: [Job]}`: the running ones and the last finished ones.
    pub const COMMAND_JOBS_LIST: &str = "terminal.command.jobs.list";
    /// `{id}` -> [`crate::contracts::service::Job`].
    pub const COMMAND_JOBS_GET: &str = "terminal.command.jobs.get";
    /// [`RunOutputParams`] with `run_id` the job id -> [`RunOutput`]: its output lines.
    pub const COMMAND_OUTPUT_READ: &str = "terminal.command.output.read";
}

pub mod topics {
    /// [`OutputEvent`] `{term_id, data}` - raw output bytes, base64, coalesced to about every 16 ms.
    pub const OUTPUT: &str = "terminal.output";
    /// [`ExitEvent`] `{term_id, exit_code}`
    pub const EXIT: &str = "terminal.exit";
    /// [`Run`]: a command started (shell integration mark C).
    pub const RUN_STARTED: &str = "terminal.run.started";
    /// [`Run`]: a command finished (mark D), with its exit code, duration and output summary.
    pub const RUN_FINISHED: &str = "terminal.run.finished";
    /// [`TermState`]: the shell's state changed (folder, prompt, attention).
    pub const STATE_CHANGED: &str = "terminal.state";
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputEvent {
    pub term_id: String,
    /// Standard base64 of the raw bytes.
    pub data: String,
    /// Sequence number of this chunk within the terminal (starts at 1, no gaps).
    #[serde(default)]
    pub seq: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExitEvent {
    pub term_id: String,
    pub exit_code: i32,
    /// Name of the signal that ended the process, if one did.
    #[serde(default)]
    pub signal: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OpenParams {
    pub cwd: String,
    #[serde(default = "default_cols")]
    pub cols: u16,
    #[serde(default = "default_rows")]
    pub rows: u16,
    /// Default: the user's login shell.
    #[serde(default)]
    pub shell: Option<String>,
    /// Arguments for `shell`; default `-l` (a login shell). A program that is not a shell (for
    /// example `docker` with `exec -it <container> bash -l` for a project that runs in a container)
    /// gets exactly these.
    #[serde(default)]
    pub args: Option<Vec<String>>,
    /// The chat session that owns this terminal, if one does: its shell is linked to it in the
    /// graph (`(:Shell)-[:FOR]->(:Session)`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
}

fn default_cols() -> u16 {
    120
}
fn default_rows() -> u16 {
    32
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TermInfo {
    pub term_id: String,
    pub cwd: String,
    pub pid: u32,
    pub cols: u16,
    pub rows: u16,
    pub alive: bool,
    /// The shell executable.
    #[serde(default)]
    pub shell: String,
    /// Set once the shell has exited.
    #[serde(default)]
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WriteParams {
    pub term_id: String,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResizeParams {
    pub term_id: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TermParams {
    pub term_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ListResult {
    pub terminals: Vec<TermInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Snapshot {
    pub term_id: String,
    /// Visible screen, one line per row (trailing blanks trimmed).
    pub text: String,
    pub cursor_row: u16,
    pub cursor_col: u16,
    #[serde(default)]
    pub cols: u16,
    #[serde(default)]
    pub rows: u16,
    #[serde(default)]
    pub alive: bool,
    /// The program switched to the alternate screen (full-screen apps such as vim or less).
    #[serde(default)]
    pub alternate_screen: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StateParams {
    pub term_id: String,
}

/// The shell's state, from its integration marks (OSC 133 prompt/command/exit, OSC 7 folder).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct TermState {
    pub term_id: String,
    pub cwd: String,
    /// The shell integration is active (marks were seen).
    #[serde(default)]
    pub integrated: bool,
    /// Waiting at a prompt (between marks A/B and C).
    #[serde(default)]
    pub at_prompt: bool,
    /// The Run in progress, if any.
    #[serde(default)]
    pub running: Option<Run>,
    #[serde(default)]
    pub last_exit: Option<i32>,
    #[serde(default)]
    pub alternate_screen: bool,
    /// idle | running | input (a program waits for input) | failed | bell
    #[serde(default)]
    pub attention: String,
    /// The git branch of `cwd`, when it is in a repository.
    #[serde(default)]
    pub git_branch: Option<String>,
    /// The running command waits for an answer (its last line is a prompt, or the terminal stopped
    /// echoing for a password).
    #[serde(default)]
    pub ask: Option<Ask>,
    /// The Keychain key whose secret was filled in during the running command.
    #[serde(default)]
    pub keychain: Option<String>,
}

/// What a running command asks.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Ask {
    /// confirm (yes/no) | text | secret (the terminal does not echo)
    pub kind: String,
    /// The prompt: the command's last line, without the answer it may already hold.
    pub text: String,
    /// The answer a bare return gives: `y` or `n` for `[Y/n]`, the text in `(...)` for a prompt.
    #[serde(default)]
    pub default: Option<String>,
    /// For confirm: the yes and the no answer as the prompt spells them (`y`/`n`, `yes`/`no`).
    #[serde(default)]
    pub options: Vec<String>,
    /// The program that asks (the newest process in the terminal's foreground group).
    #[serde(default)]
    pub program: String,
    /// Where a secret is kept in the Keychain: `<program> · <prompt>`.
    #[serde(default)]
    pub key: String,
    /// The secret filled in from the Keychain for this prompt was refused (the same prompt came
    /// again), so it is asked instead.
    #[serde(default)]
    pub refused: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AskAnswerParams {
    pub term_id: String,
    pub text: String,
    #[serde(default)]
    pub remember: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AskForgetParams {
    pub key: String,
}

/// One command and its output, recorded.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Run {
    pub id: String,
    pub term_id: String,
    pub command: String,
    pub cwd: String,
    /// Unix milliseconds.
    pub started: u64,
    #[serde(default)]
    pub ended: Option<u64>,
    #[serde(default)]
    pub exit_code: Option<i32>,
    #[serde(default)]
    pub duration_ms: u64,
    #[serde(default)]
    pub lines: u64,
    #[serde(default)]
    pub bytes: u64,
    /// raw | json | logfmt | log (detected from the output)
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub errors: u64,
    #[serde(default)]
    pub warnings: u64,
    /// user | agent
    #[serde(default)]
    pub author: String,
    /// The program used the full screen (vim, htop): its output is not kept as lines.
    #[serde(default)]
    pub fullscreen: bool,
    /// Median duration of earlier Runs of the same command in the same folder (0: none).
    #[serde(default)]
    pub usual_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RunsParams {
    #[serde(default)]
    pub term_id: Option<String>,
    /// Text in the command or folder.
    #[serde(default)]
    pub query: String,
    #[serde(default)]
    pub failed_only: bool,
    /// 0 = 100.
    #[serde(default)]
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RunList {
    pub runs: Vec<Run>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RunOutputParams {
    pub run_id: String,
    /// First line (0-based) of the window; negative counts from the end (-200 = the last 200).
    #[serde(default)]
    pub from: i64,
    /// 0 = 500.
    #[serde(default)]
    pub count: u32,
    /// Keep lines containing this text (case-insensitive), or with `level>=warn` / `level>=error`.
    #[serde(default)]
    pub filter: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct OutputLine {
    /// 0-based line number in the Run's output.
    pub n: u64,
    pub text: String,
    /// error | warn | info | debug | "" (detected)
    #[serde(default)]
    pub level: String,
    /// Unix milliseconds the line arrived.
    #[serde(default)]
    pub at: u64,
    /// The same line with its colour and style codes kept (SGR `ESC[...m` only; every other
    /// escape removed), for showing the output as the program coloured it. Empty when it had none.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub ansi: String,
    /// The line held invisible characters (zero-width, direction marks, Unicode tags) or control
    /// characters; they were removed from `text` and `ansi`, so people and the model read the same.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub hidden: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct RunOutput {
    pub run_id: String,
    pub total: u64,
    /// Lines matching the filter (all lines when there is none).
    pub matched: u64,
    pub lines: Vec<OutputLine>,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HistogramParams {
    pub run_id: String,
    /// 0 = 40.
    #[serde(default)]
    pub buckets: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Bucket {
    /// Unix milliseconds the bucket starts.
    pub at: u64,
    pub info: u64,
    pub warn: u64,
    pub error: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Histogram {
    pub run_id: String,
    pub bucket_ms: u64,
    pub buckets: Vec<Bucket>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AssessParams {
    /// The terminal whose folder, PATH and aliases apply.
    pub term_id: String,
    pub input: String,
    /// The input was pasted (not typed): encoded or many-step commands read as a stronger warning.
    #[serde(default)]
    pub pasted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Assessment {
    /// shell | ask | unsure: what the input most likely is. A leading `?` is ask, `!` is shell.
    pub kind: String,
    /// The input with a leading `?` / `!` removed.
    pub text: String,
    /// The resolved program of the first command (`/bin/rm`), when it is a shell command.
    #[serde(default)]
    pub program: Option<String>,
    pub cwd: String,
    /// read | write | network | delete | admin | unknown: the highest of every command in it.
    pub risk: String,
    /// Run without asking (risk `read` and nothing dynamic).
    pub safe: bool,
    /// Why, in short phrases (`deletes files`, `runs as root`, `command substitution`).
    #[serde(default)]
    pub reasons: Vec<String>,
    /// What the globs and paths in it match, when it has any.
    #[serde(default)]
    pub matches: Option<GlobMatches>,
    /// The command opens a full-screen tool CortexTerm has its own view for (`nano`, `htop`,
    /// `less`, `man`, `top`): `editor` | `process` | `viewer` | `man`.
    #[serde(default)]
    pub native_view: Option<String>,
    /// The file the native view opens, when there is one.
    #[serde(default)]
    pub native_target: Option<String>,
    /// What the paste guard found (stealer shapes, secrets sent out, hidden text). Any threat
    /// makes it not safe and at least `unknown`; a high one always asks first.
    #[serde(default)]
    pub threats: Vec<Threat>,
}

/// One finding of the paste guard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Threat {
    /// The rule's id (`pipe-to-shell`, `fake-password-prompt`, `hidden-text`, ...).
    pub rule: String,
    /// high | medium
    pub severity: String,
    /// One plain sentence: what it would do.
    pub text: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScanParams {
    pub text: String,
    /// It came from the clipboard (see [`AssessParams::pasted`]).
    #[serde(default)]
    pub pasted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScanResult {
    pub threats: Vec<Threat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct ScriptFetchParams {
    /// An http(s) URL.
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Script {
    /// The URL it came from after redirects.
    pub url: String,
    /// The script (about the first 200 KB of it).
    pub text: String,
    /// Its whole size.
    pub bytes: u64,
    /// More than `text` holds.
    #[serde(default)]
    pub truncated: bool,
    pub threats: Vec<Threat>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Package {
    /// OSV's name: npm | PyPI | crates.io | RubyGems
    pub ecosystem: String,
    pub name: String,
    #[serde(default)]
    pub version: Option<String>,
    /// OSV ids of known malware (`MAL-...`).
    #[serde(default)]
    pub malicious: Vec<String>,
    /// OSV ids of known vulnerabilities in that version (only when a version is named).
    #[serde(default)]
    pub vulns: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PackageCheck {
    pub packages: Vec<Package>,
    /// Why the lookup could not be made (offline, OSV not answering); the packages are listed
    /// unchecked.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct SandboxParams {
    /// The terminal whose folder the command may write.
    pub term_id: String,
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Sandboxed {
    /// `sandbox-exec -f <profile> /bin/sh -c '<command>'`.
    pub command: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct GlobMatches {
    pub files: u64,
    pub dirs: u64,
    pub bytes: u64,
    /// The first few, for the preview.
    #[serde(default)]
    pub sample: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CompleteParams {
    pub term_id: String,
    pub line: String,
    /// Byte offset of the cursor in `line`.
    pub cursor: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Completion {
    pub value: String,
    /// command | file | dir | branch | flag | history | host | process
    pub kind: String,
    #[serde(default)]
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Completions {
    /// Byte offset in `line` where the completed word starts (it is replaced by `value`).
    pub from: u32,
    pub items: Vec<Completion>,
    /// A whole-line suggestion from history (ghost text), when one fits the line so far.
    #[serde(default)]
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Place {
    pub path: String,
    pub runs: u64,
    /// Unix milliseconds.
    pub last: u64,
    #[serde(default)]
    pub git: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct PlaceList {
    pub places: Vec<Place>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FileReadParams {
    /// Absolute, or relative to `cwd`.
    pub path: String,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FileText {
    /// The absolute path.
    pub path: String,
    /// Empty for a file that does not exist yet (`exists: false`).
    pub text: String,
    pub exists: bool,
    /// The current user may write it (or create it in its folder).
    pub writable: bool,
    /// Unix milliseconds of the last change, to detect a change on disk before saving.
    #[serde(default)]
    pub modified: u64,
    pub bytes: u64,
    /// Over the editor's limit (about 30 MB) or not UTF-8: open it read-only in a viewer instead.
    #[serde(default)]
    pub too_large: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FileWriteParams {
    pub path: String,
    pub text: String,
    /// The `modified` the editor read: a newer file on disk is refused with `conflict`.
    #[serde(default)]
    pub expected_modified: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct FileWritten {
    pub path: String,
    pub modified: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct HabitsParams {
    pub cwd: String,
    /// 0 = 8.
    #[serde(default)]
    pub limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Habit {
    pub command: String,
    pub runs: u64,
    /// Share of its Runs that ended with exit 0 (0..1).
    pub success: f32,
    pub usual_ms: u64,
    /// Unix milliseconds.
    pub last: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct Habits {
    pub cwd: String,
    pub habits: Vec<Habit>,
    /// Short learned facts about the place (`builds with make dev`, `failed runs are usually fixed
    /// by docker compose up -d db`).
    #[serde(default)]
    pub notes: Vec<String>,
}

/// One command for `terminal.command.run`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct CommandRunParams {
    pub command: String,
    /// The folder it runs in (absolute; `~` is the home folder). In the sandbox it is the folder
    /// the command may write.
    pub cwd: String,
    /// Extra environment for this command.
    #[serde(default)]
    pub env: std::collections::BTreeMap<String, String>,
    /// Stopped after this long (0: 10 minutes; a `background` one: 24 hours).
    #[serde(default)]
    pub timeout_ms: u64,
    #[serde(flatten)]
    pub options: crate::contracts::service::RunOptions,
    /// Stamped by the mesh for a call from another app.
    #[serde(default)]
    pub caller: Option<crate::contracts::service::Caller>,
}

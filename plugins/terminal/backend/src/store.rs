//! The Run store: the terminal's part of the graph the memory plugin serves (`memory@1`,
//! `docs/GRAPH-MODEL.md`, "Terminal"). Nothing is written to a file.
//!
//! - **Graph** (OBSERVED layer): `(:Shell {key: term_id, shell, started_ms})-[:ON]->(:Machine)`
//!   and `-[:FOR]->(:Session)` when a session owns it; `(:CommandRun {key: run id, command,
//!   started_ms, finished_ms, exit_code, duration_ms, lines, bytes, errors, warnings, format, author,
//!   fullscreen, usual_ms})` `-[:IN_SHELL]->(:Shell)`, `-[:IN]->(:Folder {key: path})` (with the
//!   folder's chain `(:Folder)-[:IN]->(:Folder)` up to the home folder, or `/`), `-[:RAN]->(:Program
//!   {key: name, path})` for each program the line runs, `-[:FOLLOWS]->(:CommandRun)` the previous
//!   Run in the same shell; `(:Repo {key: root, remote})-[:AT]->(:Folder)` when the folder is in a
//!   git repository. (`ended_ms` is the memory plugin's own, for retired nodes: a Run's end is
//!   `finished_ms`.)
//! - **Streams**: `shell.<term_id>`, every Run's `started` and `finished` events in order (the
//!   shell's command history; the record is the Run with `event`); `run.<id>.output`, the Run's
//!   output lines (30 days), one record per line `{at, level, text, ansi?}`: line `n` is offset `n`.
//!
//! Writes never wait: Runs, events and lines go into an in-process outbox that a writer task sends
//! every 200 ms (sooner when many lines wait), each Run with its edges in one `memory.graph.put`.
//! While the memory plugin is unavailable (starting, restarting) the outbox keeps everything,
//! bounded, and is sent when it is back; nothing falls back to a file. What the completion, the
//! "first time" check and `usual_ms` need on every keystroke or Run is an in-memory index of the
//! history, read from the graph once.

use crate::{logs, threat};
use cc_protocol::contracts::memory::{
    GraphEdge, GraphNode, GraphPutParams, GraphQueryResult, GraphRef, MachineInfo, StreamAppendParams, StreamReadResult, StreamTopicsResult,
    methods as memory,
};
use cc_protocol::contracts::terminal::{Bucket, Habit, Histogram, OutputLine, Place, Run, RunOutput, RunOutputParams, RunsParams};
use cc_protocol::{BoxFuture, RpcError, codes};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Notify;

/// Calls a `memory.*` method (through the frame).
pub type Memory = Arc<dyn Fn(&'static str, Value) -> BoxFuture<'static, Result<Value, RpcError>> + Send + Sync>;

/// A Run keeps at most this much output text; the rest is counted, not kept.
pub const OUTPUT_CAP: u64 = 50 * 1024 * 1024;
/// The writer sends the outbox this often...
const FLUSH: Duration = Duration::from_millis(200);
/// ...or as soon as this many output lines wait.
const FLUSH_LINES: usize = 2000;
/// While the memory plugin is away, output lines wait up to this much text; later lines are
/// counted and dropped (Runs and their events always wait).
const MAX_WAITING_BYTES: usize = 64 * 1024 * 1024;
/// A Run's output is kept this long; a shell's history for good (ten years).
const OUTPUT_DAYS: u32 = 30;
const SHELL_DAYS: u32 = 3650;
/// Nodes and edges per `memory.graph.put` (the plugin takes 5000).
const PUT_MAX: usize = 4000;
/// Records per stream call and rows per query page (the plugin's maximum).
const PAGE: u32 = 5000;
/// The history index reads at most this many Runs.
const HISTORY_MAX: u64 = 100_000;
/// Below this many different command shapes in the history, nothing is "the first time" yet.
const SHAPES_MIN: usize = 30;
/// Durations kept per command and folder for `usual_ms`.
const USUAL_KEEP: usize = 50;
/// Programs linked per Run.
const PROGRAMS_MAX: usize = 8;

/// One output line.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Line {
    pub at: u64,
    pub level: String,
    pub text: String,
    /// The line with its SGR codes; empty when it had none.
    pub ansi: String,
}

impl Line {
    /// The stream record.
    pub fn record(&self) -> Value {
        let mut record = json!({"at": self.at, "level": self.level, "text": self.text});
        if !self.ansi.is_empty() {
            record["ansi"] = Value::String(self.ansi.clone());
        }
        record
    }

    fn from_record(value: &Value) -> Self {
        let text = |key: &str| value.get(key).and_then(Value::as_str).unwrap_or("").to_owned();
        Line { at: value.get("at").and_then(Value::as_u64).unwrap_or(0), level: text("level"), text: text("text"), ansi: text("ansi") }
    }

    /// What it counts against [`OUTPUT_CAP`].
    pub fn size(&self) -> u64 {
        (self.text.len() + self.ansi.len() + 1) as u64
    }
}

/// What the graph says about a shell besides its id.
#[derive(Debug, Clone, Default)]
pub struct ShellInfo {
    /// The shell's program (`/bin/zsh`).
    pub shell: String,
    /// When it started; unknown for a shell taken over from an earlier instance.
    pub started_ms: Option<u64>,
    /// The session that owns it.
    pub session: Option<String>,
}

/// `$CORTEX_PLUGIN_DATA`, else `$CORTEX_HOME/plugins-data/terminal`: generated sandbox profiles,
/// and where an earlier version kept `runs.db` (imported once, see [`crate::migrate`]).
pub fn default_dir() -> Option<PathBuf> {
    if let Some(dir) = std::env::var_os("CORTEX_PLUGIN_DATA").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(dir));
    }
    std::env::var_os("CORTEX_HOME").filter(|v| !v.is_empty()).map(|home| PathBuf::from(home).join("plugins-data").join("terminal"))
}

/// Whether `dir` is inside a git repository (a `.git` in it or above it).
pub fn in_git(dir: &Path) -> bool {
    dir.ancestors().any(|d| d.join(".git").exists())
}

/// Run ids are ours (`run-<hex>`); anything else never becomes a topic.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty() && id.len() < 80 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

/// A stream topic segment: `[a-z0-9._-]`.
fn segment(id: &str) -> String {
    id.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') { c.to_ascii_lowercase() } else { '-' }).collect()
}

pub fn output_topic(run_id: &str) -> String {
    format!("run.{}.output", segment(run_id))
}

pub fn shell_topic(term_id: &str) -> String {
    format!("shell.{}", segment(term_id))
}

/// A shell event record: the Run, with `event` (`started` | `finished`).
pub fn event(kind: &str, run: &Run) -> Value {
    let mut value = serde_json::to_value(run).unwrap_or_else(|_| json!({}));
    value["event"] = Value::String(kind.to_owned());
    value
}

/// The memory plugin is starting, restarting, busy or older than this plugin: try again later.
pub fn retryable(error: &RpcError) -> bool {
    error.retryable || matches!(error.code.as_str(), codes::UNAVAILABLE | codes::UNKNOWN_METHOD | codes::TIMEOUT | codes::BUSY | codes::DRAINING | codes::CONNECTION_CLOSED | codes::CANCELLED)
}

/// The folder and the folders above it, up to the home folder for one below it, else up to `/`
/// (the chain the memory plugin also links projects into).
pub fn folder_chain(path: &str) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let home = home.trim_end_matches('/');
    let mut chain = Vec::new();
    let mut at = Some(Path::new(path));
    while let Some(dir) = at {
        let key = dir.to_string_lossy().into_owned();
        if key.is_empty() {
            break;
        }
        let top = key == home || key == "/";
        chain.push(key);
        if top {
            break;
        }
        at = dir.parent();
    }
    chain
}

/// A folder as a graph key: absolute, without a trailing `/` (`/` itself stays).
pub fn folder_key(cwd: &str) -> Option<String> {
    if !cwd.starts_with('/') {
        return None;
    }
    let trimmed = cwd.trim_end_matches('/');
    Some(if trimmed.is_empty() { "/".to_owned() } else { trimmed.to_owned() })
}

fn node(label: &str, key: &str, props: Map<String, Value>) -> GraphNode {
    GraphNode { label: label.into(), key: key.into(), props, ..GraphNode::default() }
}

fn edge(from: (&str, &str), rel: &str, to: (&str, &str)) -> GraphEdge {
    GraphEdge {
        from: GraphRef { label: from.0.into(), key: from.1.into() },
        rel: rel.into(),
        to: GraphRef { label: to.0.into(), key: to.1.into() },
        ..GraphEdge::default()
    }
}

/// A CommandRun's properties.
fn run_props(run: &Run) -> Map<String, Value> {
    let mut props = Map::new();
    props.insert("command".into(), json!(run.command));
    props.insert("started_ms".into(), json!(run.started));
    props.insert("finished_ms".into(), run.ended.map_or(Value::Null, |v| json!(v)));
    props.insert("exit_code".into(), run.exit_code.map_or(Value::Null, |v| json!(v)));
    props.insert("duration_ms".into(), json!(run.duration_ms));
    props.insert("lines".into(), json!(run.lines));
    props.insert("bytes".into(), json!(run.bytes));
    props.insert("errors".into(), json!(run.errors));
    props.insert("warnings".into(), json!(run.warnings));
    props.insert("format".into(), json!(run.format));
    props.insert("author".into(), json!(run.author));
    props.insert("fullscreen".into(), json!(run.fullscreen));
    props.insert("usual_ms".into(), json!(run.usual_ms));
    props
}

/// The Run columns every Run query returns, in this order (`r` the CommandRun, `s` its Shell,
/// `f` its Folder).
const RUN_COLUMNS: &str = "r.key, s.key, f.key, r.command, r.started_ms, r.finished_ms, r.exit_code, r.duration_ms, r.lines, r.bytes, \
    r.format, r.errors, r.warnings, r.author, r.fullscreen, r.usual_ms";

fn row_run(row: &[Value]) -> Run {
    let s = |i: usize| row.get(i).and_then(Value::as_str).unwrap_or("").to_owned();
    let u = |i: usize| row.get(i).and_then(Value::as_u64).unwrap_or(0);
    Run {
        id: s(0),
        term_id: s(1),
        cwd: s(2),
        command: s(3),
        started: u(4),
        ended: row.get(5).and_then(Value::as_u64),
        exit_code: row.get(6).and_then(Value::as_i64).map(|v| v as i32),
        duration_ms: u(7),
        lines: u(8),
        bytes: u(9),
        format: s(10),
        errors: u(11),
        warnings: u(12),
        author: s(13),
        fullscreen: row.get(14).and_then(Value::as_bool).unwrap_or(false),
        usual_ms: u(15),
    }
}

/// Whether a Run matches `terminal.runs`' filters.
fn matches(run: &Run, params: &RunsParams) -> bool {
    let query = params.query.trim().to_lowercase();
    params.term_id.as_ref().is_none_or(|term| *term == run.term_id)
        && (query.is_empty() || run.command.to_lowercase().contains(&query) || run.cwd.to_lowercase().contains(&query))
        && (!params.failed_only || run.exit_code.is_some_and(|code| code != 0))
}

fn median(mut values: Vec<u64>) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}

/// A waiting Run as the writer reads it: the Run, its shell's PATH, the Run before it, its seq.
type Snapshot = (Run, Option<String>, Option<Option<String>>, u64);
/// A Run a put carries: its id, seq, and whether it finished.
type Done = (String, u64, bool);

struct PendingRun {
    run: Run,
    /// The shell's PATH, for finding the programs.
    path: Option<String>,
    /// The Run before it in the same shell: `Some(None)` none, `None` not known in this process
    /// (the writer asks the graph).
    previous: Option<Option<String>>,
    /// Bumped by every change, so a put of an older state does not clear a newer one.
    seq: u64,
}

/// What waits to be sent to the memory plugin.
#[derive(Default)]
struct Outbox {
    runs: HashMap<String, PendingRun>,
    /// Shell events, in order: (topic, record).
    events: Vec<(String, Value)>,
    /// Output lines per Run id, in order.
    lines: HashMap<String, Vec<Line>>,
    waiting_lines: usize,
    waiting_bytes: usize,
    dropped: u64,
    shells: HashMap<String, ShellInfo>,
    /// The last Run started in each shell (this process).
    last_in_shell: HashMap<String, String>,
    seq: u64,
}

/// The history, in memory, for what must answer at once.
#[derive(Default)]
struct History {
    /// Whether a Run has already contributed its finished outcome.
    ids: HashMap<String, bool>,
    commands: HashMap<(String, String), CommandHistory>,
    previous: HashMap<String, Run>,
    /// The latest finished durations per command and folder: (started, duration).
    durations: HashMap<(String, String), Vec<(u64, u64)>>,
    shapes: HashSet<String>,
}

#[derive(Default)]
struct CommandHistory {
    last: u64,
    runs: u32,
    successes: u32,
    failures: u32,
    last_exit: Option<i32>,
    /// Commands observed immediately before this one, with their outcome (failed or not).
    follows: HashMap<(String, Option<bool>), u32>,
}

impl History {
    fn add(&mut self, run: &Run) {
        let Run { id, command, cwd, started, .. } = run;
        if command.is_empty() {
            return;
        }
        let known = self.ids.get(id).copied();
        let first = known.is_none();
        let finished = run.ended.is_some() && !known.unwrap_or(false);
        self.ids.insert(id.clone(), run.ended.is_some() || known.unwrap_or(false));
        let key = (command.to_owned(), cwd.to_owned());
        if first {
            self.shapes.extend(crate::habits::shapes(command));
        }
        // Background checks are not the user's habits, even when they run often.
        if run.author != "agent" && run.term_id != "service" {
            let stats = self.commands.entry(key.clone()).or_default();
            if first {
                stats.runs = stats.runs.saturating_add(1);
                if let Some(previous) = self.previous.get(&run.term_id)
                    && previous.cwd == *cwd && previous.command != *command
                    && *started > previous.started && started.saturating_sub(previous.ended.unwrap_or(previous.started)) <= 30 * 60 * 1000
                {
                    let count = stats.follows.entry((previous.command.clone(), previous.exit_code.map(|code| code != 0))).or_default();
                    *count = count.saturating_add(1);
                }
            }
            if finished {
                if run.exit_code == Some(0) {
                    stats.successes = stats.successes.saturating_add(1);
                } else if run.exit_code.is_some() {
                    stats.failures = stats.failures.saturating_add(1);
                }
            }
            if *started >= stats.last {
                stats.last = *started;
                stats.last_exit = run.exit_code;
            }
            if !run.term_id.is_empty() && self.previous.get(&run.term_id).is_none_or(|previous| *started >= previous.started) {
                self.previous.insert(run.term_id.clone(), run.clone());
            }
        }
        if run.ended.is_some() {
            let list = self.durations.entry(key).or_default();
            if !list.iter().any(|(at, _)| at == started) {
                list.push((*started, run.duration_ms));
                if list.len() > USUAL_KEEP {
                    list.sort_unstable();
                    list.remove(0);
                }
            }
        }
    }
}

/// What the writer already wrote in this process (merges are idempotent; this only keeps the
/// batches small).
#[derive(Default)]
pub(crate) struct Written {
    machine: Option<String>,
    shells: HashSet<String>,
    folders: HashSet<String>,
    programs: HashSet<String>,
    repos: HashSet<String>,
    /// Runs whose node and edges are stored and that have not finished yet.
    runs: HashSet<String>,
    /// Folder -> the root of the git repository it is in.
    repo_of: HashMap<String, Option<String>>,
    /// Program name -> where it was found.
    found: HashMap<(String, Option<String>), Option<String>>,
}

pub struct Store {
    memory: Memory,
    /// The plugin's data folder (where an earlier version's `runs.db` may wait to be imported).
    dir: Option<PathBuf>,
    outbox: Mutex<Outbox>,
    history: Mutex<History>,
    wake: Notify,
}

impl Store {
    /// The store, and its writer task (call inside the Tokio runtime).
    pub fn new(memory: Memory, dir: Option<PathBuf>) -> Arc<Self> {
        let store = Arc::new(Store { memory, dir, outbox: Mutex::default(), history: Mutex::default(), wake: Notify::new() });
        tokio::spawn(store.clone().writer());
        store
    }

    pub(crate) fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    pub(crate) async fn call<T: serde::de::DeserializeOwned>(&self, method: &'static str, params: Value) -> Result<T, RpcError> {
        let value = (self.memory)(method, params).await?;
        serde_json::from_value(value).map_err(|e| RpcError::internal(format!("{method}: {e}")))
    }

    pub(crate) async fn query(&self, cypher: &str, params: Value) -> Result<Vec<Vec<Value>>, RpcError> {
        let result: GraphQueryResult = self.call(memory::GRAPH_QUERY, json!({"cypher": cypher, "params": params, "limit": PAGE})).await?;
        Ok(result.rows)
    }

    // ---- writes (never wait) ----

    /// A shell this instance serves: what its node says.
    pub fn shell(&self, term_id: &str, info: ShellInfo) {
        crate::lock(&self.outbox).shells.insert(term_id.to_owned(), info);
    }

    /// A Run started; `path` is its shell's PATH.
    pub fn started(&self, run: &Run, path: Option<String>) {
        crate::lock(&self.history).add(run);
        let mut outbox = crate::lock(&self.outbox);
        // A shell opened by this process has no Run before its first one; for any other the
        // writer asks the graph.
        let opened_here = outbox.shells.get(&run.term_id).is_some_and(|info| info.started_ms.is_some());
        let previous = outbox.last_in_shell.insert(run.term_id.clone(), run.id.clone());
        let previous = previous.map(Some).or(opened_here.then_some(None));
        outbox.seq += 1;
        let seq = outbox.seq;
        outbox.events.push((shell_topic(&run.term_id), event("started", run)));
        outbox.runs.insert(run.id.clone(), PendingRun { run: run.clone(), path, previous, seq });
    }

    /// A Run finished.
    pub fn finished(&self, run: &Run) {
        crate::lock(&self.history).add(run);
        let mut outbox = crate::lock(&self.outbox);
        outbox.seq += 1;
        let seq = outbox.seq;
        outbox.events.push((shell_topic(&run.term_id), event("finished", run)));
        match outbox.runs.get_mut(&run.id) {
            Some(pending) => {
                pending.run = run.clone();
                pending.seq = seq;
            }
            None => {
                outbox.runs.insert(run.id.clone(), PendingRun { run: run.clone(), path: None, previous: None, seq });
            }
        }
    }

    /// Output lines of a Run, in order.
    pub fn lines(&self, run_id: &str, lines: Vec<Line>) {
        if lines.is_empty() || !valid_id(run_id) {
            return;
        }
        let wake = {
            let mut outbox = crate::lock(&self.outbox);
            let mut kept = Vec::with_capacity(lines.len());
            for line in lines {
                let size = line.size() as usize;
                if outbox.waiting_bytes + size > MAX_WAITING_BYTES {
                    outbox.dropped += 1;
                    continue;
                }
                outbox.waiting_bytes += size;
                kept.push(line);
            }
            outbox.waiting_lines += kept.len();
            outbox.lines.entry(run_id.to_owned()).or_default().extend(kept);
            outbox.waiting_lines >= FLUSH_LINES
        };
        if wake {
            self.wake.notify_one();
        }
    }

    // ---- the writer ----

    async fn writer(self: Arc<Self>) {
        let mut written = Written::default();
        let mut imported = false;
        let mut loaded = false;
        let mut backoff = Duration::ZERO;
        loop {
            if backoff.is_zero() {
                tokio::select! {
                    _ = self.wake.notified() => {}
                    _ = tokio::time::sleep(FLUSH) => {}
                }
            } else {
                tokio::time::sleep(backoff).await;
            }
            let result = async {
                if written.machine.is_none() {
                    let machine: MachineInfo = self.call(memory::GRAPH_MACHINE, json!({})).await?;
                    written.machine = Some(machine.key);
                }
                if !imported {
                    // Before anything new is sent, so a shell's stream keeps its order.
                    match crate::migrate::run(&self, &mut written).await {
                        Ok(()) => {}
                        Err(error) if retryable(&error) => return Err(error),
                        Err(error) => tracing::warn!("run store: the earlier Runs were not imported (next start tries again): {}", error.message),
                    }
                    imported = true;
                }
                if !loaded {
                    self.load_history().await?;
                    loaded = true;
                }
                self.flush(&mut written).await
            }
            .await;
            match result {
                Ok(()) => backoff = Duration::ZERO,
                Err(error) => {
                    if backoff.is_zero() {
                        tracing::info!("run store: the memory plugin is not answering ({}); Runs wait in memory", error.message);
                    }
                    backoff = (backoff * 2).clamp(Duration::from_millis(500), Duration::from_secs(10));
                }
            }
        }
    }

    /// Send what waits. A refused batch is logged and dropped; an unavailable memory plugin
    /// leaves everything waiting (the error is returned).
    async fn flush(&self, written: &mut Written) -> Result<(), RpcError> {
        self.flush_runs(written).await?;
        self.flush_events().await?;
        self.flush_lines().await
    }

    async fn flush_runs(&self, written: &mut Written) -> Result<(), RpcError> {
        let mut pending: Vec<Snapshot> = {
            let outbox = crate::lock(&self.outbox);
            outbox.runs.values().map(|p| (p.run.clone(), p.path.clone(), p.previous.clone(), p.seq)).collect()
        };
        if pending.is_empty() {
            return Ok(());
        }
        pending.sort_by(|a, b| (a.0.started, &a.0.id).cmp(&(b.0.started, &b.0.id)));
        let shells = crate::lock(&self.outbox).shells.clone();
        // The Run before each new one, when this process did not see it start.
        for (run, _, previous, _) in &mut pending {
            if previous.is_none() && !written.runs.contains(&run.id) {
                let rows = self
                    .query(
                        "MATCH (r:CommandRun)-[:IN_SHELL]->(:Shell {key: $shell}) WHERE r.started_ms < $before RETURN r.key ORDER BY r.started_ms DESC LIMIT 1",
                        json!({"shell": run.term_id, "before": run.started}),
                    )
                    .await?;
                *previous = Some(rows.first().and_then(|row| row.first()).and_then(Value::as_str).map(str::to_owned));
            }
        }
        let mut batch = Batch::default();
        let mut done: Vec<Done> = Vec::new();
        let mut parts: Vec<(Batch, Vec<Done>)> = Vec::new();
        for (run, path, previous, seq) in &pending {
            let one = self.run_batch(written, run, path.as_deref(), previous.clone().flatten(), shells.get(&run.term_id), true);
            if batch.len() + one.len() > PUT_MAX && !batch.is_empty() {
                parts.push((std::mem::take(&mut batch), std::mem::take(&mut done)));
            }
            batch.extend(one);
            done.push((run.id.clone(), *seq, run.ended.is_some()));
        }
        parts.push((batch, done));
        for (batch, done) in parts {
            match self.put(&batch).await {
                Ok(()) => written.note(&batch),
                Err(error) if retryable(&error) => return Err(error),
                Err(error) => {
                    // One Run at a time; then without the session link (a session the memory
                    // plugin does not know); then with only the edges that place it.
                    tracing::debug!("run store: a batch was refused ({}); sending its Runs one by one", error.message);
                    for (id, _, _) in &done {
                        let Some((run, path, previous, _)) = pending.iter().find(|p| &p.0.id == id) else { continue };
                        let shell = shells.get(&run.term_id);
                        let unowned = shell.map(|info| ShellInfo { session: None, ..info.clone() });
                        let tries = [
                            self.run_batch(written, run, path.as_deref(), previous.clone().flatten(), shell, true),
                            self.run_batch(written, run, path.as_deref(), previous.clone().flatten(), unowned.as_ref(), true),
                            self.run_batch(written, run, None, None, shell, false),
                        ];
                        let mut last = None;
                        for batch in tries {
                            match self.put(&batch).await {
                                Ok(()) => {
                                    written.note(&batch);
                                    last = None;
                                    break;
                                }
                                Err(error) if retryable(&error) => return Err(error),
                                Err(error) => last = Some(error),
                            }
                        }
                        if let Some(error) = last {
                            tracing::warn!("run store: Run {id} was refused by the graph: {}", error.message);
                        }
                    }
                }
            }
            let mut outbox = crate::lock(&self.outbox);
            for (id, seq, finished) in done {
                if outbox.runs.get(&id).is_some_and(|p| p.seq == seq) {
                    outbox.runs.remove(&id);
                    if finished {
                        written.runs.remove(&id);
                    }
                }
            }
        }
        Ok(())
    }

    /// The nodes and edges of one Run: its node, and (the first time) its shell, folder chain,
    /// repository, programs and the Run before it. `extras: false` keeps only what places it.
    pub(crate) fn run_batch(&self, written: &mut Written, run: &Run, path: Option<&str>, previous: Option<String>, shell: Option<&ShellInfo>, extras: bool) -> Batch {
        let mut batch = Batch::default();
        batch.nodes.push(node("CommandRun", &run.id, run_props(run)));
        if written.runs.contains(&run.id) {
            return batch;
        }
        batch.started.push(run.id.clone());
        let me = ("CommandRun", run.id.as_str());
        batch.edges.push(edge(me, "IN_SHELL", ("Shell", &run.term_id)));
        if !written.shells.contains(&run.term_id) {
            let mut props = Map::new();
            if let Some(info) = shell {
                if !info.shell.is_empty() {
                    props.insert("shell".into(), json!(info.shell));
                }
                if let Some(at) = info.started_ms {
                    props.insert("started_ms".into(), json!(at));
                }
            }
            batch.nodes.push(node("Shell", &run.term_id, props));
            if let Some(machine) = &written.machine {
                batch.edges.push(edge(("Shell", &run.term_id), "ON", ("Machine", machine)));
            }
            if extras && let Some(session) = shell.and_then(|info| info.session.as_deref()).filter(|s| !s.is_empty()) {
                batch.edges.push(edge(("Shell", &run.term_id), "FOR", ("Session", session)));
            }
            batch.shells.push(run.term_id.clone());
        }
        if let Some(folder) = folder_key(&run.cwd) {
            batch.edges.push(edge(me, "IN", ("Folder", &folder)));
            batch.folders(written, &folder);
            if extras
                && let Some(root) = written.repo(&folder)
                && !written.repos.contains(&root)
            {
                let mut props = Map::new();
                if let Some(remote) = remote(Path::new(&root)) {
                    props.insert("remote".into(), json!(remote));
                }
                batch.nodes.push(node("Repo", &root, props));
                batch.folders(written, &root);
                batch.edges.push(edge(("Repo", &root), "AT", ("Folder", &root)));
                batch.repos.push(root);
            }
        }
        if extras {
            for (name, found) in written.programs_of(&run.command, &run.cwd, path) {
                if !written.programs.contains(&name) && !batch.programs.contains(&name) {
                    let mut props = Map::new();
                    if let Some(found) = found {
                        props.insert("path".into(), json!(found));
                    }
                    batch.nodes.push(node("Program", &name, props));
                    batch.programs.push(name.clone());
                }
                batch.edges.push(edge(me, "RAN", ("Program", &name)));
            }
            if let Some(previous) = previous.filter(|p| *p != run.id) {
                batch.edges.push(edge(me, "FOLLOWS", ("CommandRun", &previous)));
            }
        }
        batch
    }

    pub(crate) async fn put(&self, batch: &Batch) -> Result<(), RpcError> {
        if batch.is_empty() {
            return Ok(());
        }
        let params = GraphPutParams { nodes: batch.nodes.clone(), edges: batch.edges.clone(), ..GraphPutParams::default() };
        let _: Value = self.call(memory::GRAPH_PUT, serde_json::to_value(&params).map_err(|e| RpcError::internal(e.to_string()))?).await?;
        Ok(())
    }

    pub(crate) async fn append(&self, topic: &str, records: Vec<Value>, days: u32) -> Result<(), RpcError> {
        for chunk in records.chunks(PAGE as usize) {
            let params = StreamAppendParams { topic: topic.to_owned(), records: chunk.to_vec(), retention_days: Some(days) };
            let _: Value = self.call(memory::STREAM_APPEND, serde_json::to_value(&params).map_err(|e| RpcError::internal(e.to_string()))?).await?;
        }
        Ok(())
    }

    async fn flush_events(&self) -> Result<(), RpcError> {
        let events = std::mem::take(&mut crate::lock(&self.outbox).events);
        if events.is_empty() {
            return Ok(());
        }
        let mut topics: Vec<(String, Vec<Value>)> = Vec::new();
        for (topic, record) in events {
            match topics.iter_mut().find(|(t, _)| *t == topic) {
                Some((_, records)) => records.push(record),
                None => topics.push((topic, vec![record])),
            }
        }
        let mut left: Vec<(String, Value)> = Vec::new();
        let mut failure = None;
        for (topic, records) in topics {
            if failure.is_some() {
                left.extend(records.into_iter().map(|r| (topic.clone(), r)));
                continue;
            }
            match self.append(&topic, records.clone(), SHELL_DAYS).await {
                Ok(()) => {}
                Err(error) if retryable(&error) => {
                    left.extend(records.into_iter().map(|r| (topic.clone(), r)));
                    failure = Some(error);
                }
                Err(error) => tracing::warn!("run store: {topic} refused {} events: {}", records.len(), error.message),
            }
        }
        if !left.is_empty() {
            let mut outbox = crate::lock(&self.outbox);
            left.append(&mut outbox.events);
            outbox.events = left;
        }
        failure.map_or(Ok(()), Err)
    }

    async fn flush_lines(&self) -> Result<(), RpcError> {
        let lines = {
            let mut outbox = crate::lock(&self.outbox);
            if outbox.dropped > 0 {
                tracing::warn!("run store: {} output lines were dropped while the memory plugin was away", outbox.dropped);
                outbox.dropped = 0;
            }
            std::mem::take(&mut outbox.lines)
        };
        let mut failure = None;
        let mut left: Vec<(String, Vec<Line>)> = Vec::new();
        for (id, lines) in lines {
            let (count, bytes) = (lines.len(), lines.iter().map(|l| l.size() as usize).sum::<usize>());
            if failure.is_some() {
                left.push((id, lines));
                continue;
            }
            match self.append(&output_topic(&id), lines.iter().map(Line::record).collect(), OUTPUT_DAYS).await {
                Ok(()) => {}
                Err(error) if retryable(&error) => {
                    left.push((id, lines));
                    failure = Some(error);
                    continue;
                }
                Err(error) => tracing::warn!("run store: the output of {id} was refused ({count} lines): {}", error.message),
            }
            let mut outbox = crate::lock(&self.outbox);
            outbox.waiting_lines = outbox.waiting_lines.saturating_sub(count);
            outbox.waiting_bytes = outbox.waiting_bytes.saturating_sub(bytes);
        }
        if !left.is_empty() {
            let mut outbox = crate::lock(&self.outbox);
            for (id, mut lines) in left {
                if let Some(newer) = outbox.lines.remove(&id) {
                    lines.extend(newer);
                }
                outbox.lines.insert(id, lines);
            }
        }
        failure.map_or(Ok(()), Err)
    }

    /// The history index, from the graph (once per process).
    async fn load_history(&self) -> Result<(), RpcError> {
        let mut skip = 0u64;
        let mut rows_all: Vec<Vec<Value>> = Vec::new();
        while skip < HISTORY_MAX {
            let rows = self
                .query(
                    "MATCH (r:CommandRun) WHERE r.command <> '' OPTIONAL MATCH (r)-[:IN]->(f:Folder) \
                     OPTIONAL MATCH (r)-[:IN_SHELL]->(s:Shell) \
                     RETURN r.key, r.command, f.key, r.started_ms, r.finished_ms, r.duration_ms, s.key, r.exit_code, r.author \
                     ORDER BY r.started_ms DESC SKIP $skip LIMIT $limit",
                    json!({"skip": skip, "limit": PAGE}),
                )
                .await?;
            let n = rows.len() as u64;
            rows_all.extend(rows);
            if n < u64::from(PAGE) {
                break;
            }
            skip += n;
        }
        let mut history = crate::lock(&self.history);
        // Reconstruct historical sequences in time order even if a live Run arrived while
        // the graph was loading; afterwards keep the newer live predecessor for each shell.
        let live_previous = std::mem::take(&mut history.previous);
        for row in rows_all.iter().rev() {
            let s = |i: usize| row.get(i).and_then(Value::as_str).unwrap_or("");
            let started = row.get(3).and_then(Value::as_u64).unwrap_or(0);
            history.add(&Run {
                id: s(0).into(), command: s(1).into(), cwd: s(2).into(), started,
                ended: row.get(4).and_then(Value::as_u64),
                duration_ms: row.get(5).and_then(Value::as_u64).unwrap_or(0),
                term_id: s(6).into(), exit_code: row.get(7).and_then(Value::as_i64).map(|code| code as i32),
                author: s(8).into(),
                ..Run::default()
            });
        }
        for (term, run) in live_previous {
            if history.previous.get(&term).is_none_or(|previous| run.started >= previous.started) {
                history.previous.insert(term, run);
            }
        }
        Ok(())
    }

    // ---- reads that answer at once (the history index) ----

    /// The shapes in `command` never run on this Mac before (empty while the history is short).
    pub fn new_shapes(&self, command: &str) -> Vec<String> {
        let history = crate::lock(&self.history);
        if history.shapes.len() < SHAPES_MIN {
            return Vec::new();
        }
        crate::habits::shapes(command).into_iter().filter(|shape| !history.shapes.contains(shape)).collect()
    }

    /// Median duration of the last finished Runs of `command` in `cwd` (0: none).
    pub fn usual_ms(&self, command: &str, cwd: &str) -> u64 {
        let history = crate::lock(&self.history);
        history.durations.get(&(command.to_owned(), cwd.to_owned())).map_or(0, |list| median(list.iter().map(|(_, d)| *d).collect()))
    }

    /// Rank actual commands by place, learned sequences, successful use and recency.
    pub fn suggestion(&self, line: &str, cwd: &str, term_id: &str) -> Option<String> {
        if line.trim().len() < 2 || line.chars().any(char::is_control) {
            return None;
        }
        let history = crate::lock(&self.history);
        let now = crate::marks::now_ms();
        let folders = crate::habits::scope(cwd);
        let previous = history.previous.get(term_id).filter(|run| now.saturating_sub(run.ended.unwrap_or(run.started)) <= 30 * 60 * 1000);
        let previous_key = previous.map(|run| (run.command.clone(), run.exit_code.map(|code| code != 0)));
        let rank = |folder: &str, stats: &CommandHistory| {
            let place = folders.iter().position(|f| f == folder).map_or(0, |depth| {
                if depth == 0 { 120 } else { 70i64.saturating_sub(depth as i64 * 10).max(10) }
            });
            let sequence = previous.filter(|run| run.cwd == folder)
                .and_then(|_| previous_key.as_ref().and_then(|key| stats.follows.get(key)))
                .copied().unwrap_or(0).min(5) as i64 * 20;
            let frequency = stats.runs.max(1).ilog2().min(6) as i64 * 6;
            let reliability = (stats.successes as i64 * 30) / (stats.successes as i64 + stats.failures as i64).max(1);
            let age_hours = now.saturating_sub(stats.last) / 3_600_000;
            let recency = 40 / (1 + age_hours.min(40) as i64);
            let failed = if stats.last_exit.is_some_and(|code| code != 0) { 45 } else { 0 };
            (place + sequence + frequency + reliability + recency - failed, stats.last)
        };
        history
            .commands
            .iter()
            .filter(|((command, _), stats)| {
                command.starts_with(line) && command != line && command.len() <= 2048
                    && !command.chars().any(char::is_control)
                    && !(stats.successes == 0 && stats.failures > 0)
            })
            .max_by(|((a_command, a_folder), a), ((b_command, b_folder), b)| {
                rank(a_folder, a).cmp(&rank(b_folder, b)).then_with(|| b_command.cmp(a_command))
            })
            .map(|((command, _), _)| command.clone())
    }

    // ---- reads from the graph and the streams ----

    /// A Run not yet sent, if it is one.
    fn waiting(&self, id: &str) -> Option<Run> {
        crate::lock(&self.outbox).runs.get(id).map(|p| p.run.clone())
    }

    pub async fn get(&self, id: &str) -> Result<Run, RpcError> {
        if let Some(run) = self.waiting(id) {
            return Ok(run);
        }
        let rows = self
            .query(
                &format!("MATCH (r:CommandRun {{key: $id}}) OPTIONAL MATCH (r)-[:IN_SHELL]->(s:Shell) OPTIONAL MATCH (r)-[:IN]->(f:Folder) RETURN {RUN_COLUMNS} LIMIT 1"),
                json!({"id": id}),
            )
            .await?;
        rows.first().map(|row| row_run(row)).ok_or_else(|| RpcError::new(codes::NOT_FOUND, format!("no run `{id}`")))
    }

    /// Recorded Runs, newest first.
    pub async fn runs(&self, params: &RunsParams) -> Result<Vec<Run>, RpcError> {
        let limit = if params.limit == 0 { 100 } else { params.limit.min(10_000) };
        let shell = if params.term_id.is_some() { "(s:Shell {key: $term})" } else { "(s:Shell)" };
        let mut filters = Vec::new();
        let query = params.query.trim().to_lowercase();
        if !query.is_empty() {
            filters.push("(toLower(r.command) CONTAINS $q OR toLower(coalesce(f.key, '')) CONTAINS $q)");
        }
        if params.failed_only {
            filters.push("r.exit_code IS NOT NULL AND r.exit_code <> 0");
        }
        let filter = if filters.is_empty() { String::new() } else { format!("WHERE {}", filters.join(" AND ")) };
        let mut runs: Vec<Run> = Vec::new();
        let mut skip = 0u32;
        let mut away = None;
        while runs.len() < limit as usize {
            let page = (limit - runs.len() as u32).min(PAGE);
            let rows = match self
                .query(
                    &format!(
                        "MATCH (r:CommandRun)-[:IN_SHELL]->{shell} OPTIONAL MATCH (r)-[:IN]->(f:Folder) WITH r, s, f {filter} \
                         RETURN {RUN_COLUMNS} ORDER BY r.started_ms DESC, r.key DESC SKIP $skip LIMIT $limit"
                    ),
                    json!({"term": params.term_id, "q": query, "skip": skip, "limit": page}),
                )
                .await
            {
                Ok(rows) => rows,
                // The memory plugin is away: the Runs that wait for it are all there is to show.
                Err(error) if retryable(&error) => {
                    away = Some(error);
                    break;
                }
                Err(error) => return Err(error),
            };
            let n = rows.len() as u32;
            runs.extend(rows.iter().map(|row| row_run(row)));
            if n < page {
                break;
            }
            skip += n;
        }
        // Runs not sent yet (the newest, or all of them while the memory plugin is away).
        let waiting: Vec<Run> = crate::lock(&self.outbox).runs.values().map(|p| p.run.clone()).filter(|run| matches(run, params)).collect();
        for run in waiting {
            match runs.iter_mut().find(|r| r.id == run.id) {
                Some(stored) => *stored = run,
                None => runs.push(run),
            }
        }
        if let Some(error) = away
            && runs.is_empty()
        {
            return Err(error);
        }
        runs.sort_by(|a, b| (b.started, &b.id).cmp(&(a.started, &a.id)));
        runs.truncate(limit as usize);
        Ok(runs)
    }

    /// Folders the Runs happened in, most used first.
    pub async fn places(&self, limit: u32) -> Result<Vec<Place>, RpcError> {
        let limit = if limit == 0 { 50 } else { limit.min(1000) };
        let rows = self
            .query(
                "MATCH (r:CommandRun)-[:IN]->(f:Folder) RETURN f.key AS path, count(r) AS n, max(r.started_ms) AS last ORDER BY n DESC, last DESC LIMIT $limit",
                json!({"limit": limit}),
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| {
                let path = row.first().and_then(Value::as_str).unwrap_or("").to_owned();
                let git = in_git(Path::new(&path));
                Place { path, runs: row.get(1).and_then(Value::as_u64).unwrap_or(0), last: row.get(2).and_then(Value::as_u64).unwrap_or(0), git }
            })
            .collect())
    }

    /// The commands run in any of `folders`, most used first: how many Runs, the share that
    /// ended with exit 0, the median duration and the last time.
    pub async fn habits(&self, folders: &[String], limit: u32) -> Result<Vec<Habit>, RpcError> {
        if folders.is_empty() {
            return Ok(Vec::new());
        }
        let rows = self
            .query(
                "MATCH (r:CommandRun)-[:IN]->(f:Folder) WHERE f.key IN $folders AND r.command <> '' AND r.finished_ms IS NOT NULL \
                 RETURN r.command AS command, count(r) AS n, sum(CASE WHEN r.exit_code = 0 THEN 1 ELSE 0 END) AS ok, \
                 sum(CASE WHEN r.exit_code IS NOT NULL THEN 1 ELSE 0 END) AS coded, max(r.started_ms) AS last, collect(r.duration_ms) AS durations \
                 ORDER BY n DESC, last DESC LIMIT $limit",
                json!({"folders": folders, "limit": limit.clamp(1, 200)}),
            )
            .await?;
        Ok(rows
            .iter()
            .map(|row| {
                let u = |i: usize| row.get(i).and_then(Value::as_u64).unwrap_or(0);
                let (ok, coded) = (u(2) as f32, u(3) as f32);
                let durations = row.get(5).and_then(Value::as_array).map(|list| list.iter().filter_map(Value::as_u64).collect()).unwrap_or_default();
                Habit {
                    command: row.first().and_then(Value::as_str).unwrap_or("").to_owned(),
                    runs: u(1),
                    success: if coded > 0.0 { ok / coded } else { 0.0 },
                    usual_ms: median(durations),
                    last: u(4),
                }
            })
            .collect())
    }

    /// The last finished Runs in `cwd`, oldest first.
    pub async fn folder_runs(&self, cwd: &str, limit: u32) -> Result<Vec<Run>, RpcError> {
        let rows = self
            .query(
                &format!(
                    "MATCH (r:CommandRun)-[:IN]->(f:Folder {{key: $cwd}}) WHERE r.command <> '' AND r.finished_ms IS NOT NULL \
                     OPTIONAL MATCH (r)-[:IN_SHELL]->(s:Shell) RETURN {RUN_COLUMNS} ORDER BY r.started_ms DESC LIMIT $limit"
                ),
                json!({"cwd": cwd, "limit": limit.min(PAGE)}),
            )
            .await?;
        let mut runs: Vec<Run> = rows.iter().map(|row| row_run(row)).collect();
        runs.reverse();
        Ok(runs)
    }

    /// The offset after a Run's last stored line (its line count).
    pub async fn stored_lines(&self, run_id: &str) -> Result<u64, RpcError> {
        let topic = output_topic(run_id);
        let topics: StreamTopicsResult = self.call(memory::STREAM_TOPICS, json!({"prefix": topic})).await?;
        Ok(topics.topics.iter().find(|t| t.name == topic).map_or(0, |t| t.next_offset))
    }

    /// A Run's stored lines from `from` (`count` at most, 0: all), with their numbers, then the
    /// ones still waiting to be sent.
    async fn read_lines(&self, run_id: &str, from: u64, count: u64) -> Result<Vec<(u64, Line)>, RpcError> {
        if !valid_id(run_id) {
            return Err(RpcError::invalid_params(format!("bad run id `{run_id}`")));
        }
        let topic = output_topic(run_id);
        let mut lines = Vec::new();
        let mut offset = from;
        loop {
            let want = if count == 0 { u64::from(PAGE) } else { (count - lines.len() as u64).min(u64::from(PAGE)) };
            if want == 0 {
                break;
            }
            let page: StreamReadResult = self.call(memory::STREAM_READ, json!({"topic": topic, "from_offset": offset, "limit": want})).await?;
            let n = page.records.len();
            lines.extend(page.records.iter().map(|r| (r.offset, Line::from_record(&r.value))));
            offset = page.next_offset;
            if page.end || n == 0 {
                break;
            }
        }
        let next = offset;
        let waiting: Vec<Line> = crate::lock(&self.outbox).lines.get(run_id).cloned().unwrap_or_default();
        for (i, line) in waiting.into_iter().enumerate() {
            let n = next + i as u64;
            if n >= from && (count == 0 || (lines.len() as u64) < count) {
                lines.push((n, line));
            }
        }
        Ok(lines)
    }

    /// How many lines a Run has (stored and waiting).
    async fn total_lines(&self, run_id: &str) -> Result<u64, RpcError> {
        let stored = self.stored_lines(run_id).await?;
        let waiting = crate::lock(&self.outbox).lines.get(run_id).map_or(0, Vec::len) as u64;
        Ok(stored + waiting)
    }

    pub async fn output(&self, params: &RunOutputParams) -> Result<RunOutput, RpcError> {
        let run = self.get(&params.run_id).await?;
        let filter = params.filter.trim();
        let min_level = filter.strip_prefix("level>=").map(str::trim);
        let needle = filter.to_lowercase();
        let count = if params.count == 0 { 500 } else { params.count as usize };
        let (total, matched, window): (u64, u64, Vec<(u64, Line)>) = if filter.is_empty() {
            // Only the window is read.
            let total = self.total_lines(&params.run_id).await?;
            let start = if params.from < 0 { total.saturating_sub(params.from.unsigned_abs()) } else { (params.from as u64).min(total) };
            let window = if start >= total { Vec::new() } else { self.read_lines(&params.run_id, start, count as u64).await? };
            (total, total, window)
        } else {
            let lines = self.read_lines(&params.run_id, 0, 0).await?;
            let total = lines.len() as u64;
            let matched: Vec<(u64, Line)> = lines
                .into_iter()
                .filter(|(_, line)| match min_level {
                    Some(min) => logs::at_least(&line.level, min),
                    None => line.text.to_lowercase().contains(&needle),
                })
                .collect();
            let start = if params.from < 0 {
                matched.len().saturating_sub(params.from.unsigned_abs() as usize)
            } else {
                (params.from as usize).min(matched.len())
            };
            let n = matched.len() as u64;
            (total, n, matched.into_iter().skip(start).take(count).collect())
        };
        Ok(RunOutput {
            run_id: run.id,
            total,
            matched,
            // Hidden characters and stray control codes never reach a reader, person or model.
            lines: window
                .into_iter()
                .map(|(n, line)| {
                    let (text, hidden) = threat::clean(&line.text);
                    let ansi = if line.ansi.is_empty() { String::new() } else { threat::clean_ansi(&line.ansi) };
                    OutputLine { n, text, level: line.level, at: line.at, ansi, hidden }
                })
                .collect(),
            format: run.format,
        })
    }

    pub async fn histogram(&self, run_id: &str, buckets: u32) -> Result<Histogram, RpcError> {
        let run = self.get(run_id).await?;
        let lines = self.read_lines(run_id, 0, 0).await?;
        let n = if buckets == 0 { 40 } else { buckets.min(2000) } as u64;
        let start = run.started;
        let last = lines.iter().map(|(_, l)| l.at).max().unwrap_or(start);
        let end = run.ended.unwrap_or(last).max(last).max(start + 1);
        let bucket_ms = (end - start).div_ceil(n).max(1);
        let mut out: Vec<Bucket> = (0..n).map(|i| Bucket { at: start + i * bucket_ms, ..Bucket::default() }).collect();
        for (_, line) in &lines {
            let index = (line.at.saturating_sub(start) / bucket_ms).min(n - 1) as usize;
            let bucket = &mut out[index];
            match line.level.as_str() {
                "error" => bucket.error += 1,
                "warn" => bucket.warn += 1,
                _ => bucket.info += 1,
            }
        }
        Ok(Histogram { run_id: run.id, bucket_ms, buckets: out })
    }
}

/// Nodes and edges for one `memory.graph.put`, and what they make known.
#[derive(Default, Clone)]
pub(crate) struct Batch {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
    started: Vec<String>,
    shells: Vec<String>,
    folders: Vec<String>,
    programs: Vec<String>,
    repos: Vec<String>,
}

impl Batch {
    pub fn len(&self) -> usize {
        self.nodes.len() + self.edges.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty() && self.edges.is_empty()
    }

    pub fn extend(&mut self, other: Batch) {
        self.nodes.extend(other.nodes);
        self.edges.extend(other.edges);
        self.started.extend(other.started);
        self.shells.extend(other.shells);
        self.folders.extend(other.folders);
        self.programs.extend(other.programs);
        self.repos.extend(other.repos);
    }

    /// `folder` and its chain, as far as not written yet.
    fn folders(&mut self, written: &Written, folder: &str) {
        let chain = folder_chain(folder);
        for (i, key) in chain.iter().enumerate() {
            if written.folders.contains(key) || self.folders.contains(key) {
                break;
            }
            self.nodes.push(node("Folder", key, Map::new()));
            if let Some(parent) = chain.get(i + 1) {
                self.edges.push(edge(("Folder", key), "IN", ("Folder", parent)));
            }
            self.folders.push(key.clone());
        }
    }
}

impl Written {
    pub fn forget_run(&mut self, id: &str) {
        self.runs.remove(id);
    }

    pub fn note(&mut self, batch: &Batch) {
        self.runs.extend(batch.started.iter().cloned());
        self.shells.extend(batch.shells.iter().cloned());
        self.folders.extend(batch.folders.iter().cloned());
        self.programs.extend(batch.programs.iter().cloned());
        self.repos.extend(batch.repos.iter().cloned());
    }

    /// The root of the git repository `folder` is in (cached).
    fn repo(&mut self, folder: &str) -> Option<String> {
        if let Some(root) = self.repo_of.get(folder) {
            return root.clone();
        }
        let root = Path::new(folder).ancestors().find(|d| d.join(".git").exists()).map(|d| d.to_string_lossy().into_owned());
        if self.repo_of.len() > 10_000 {
            self.repo_of.clear();
        }
        self.repo_of.insert(folder.to_owned(), root.clone());
        root
    }

    /// The programs a command line runs: (name, where it was found).
    fn programs_of(&mut self, command: &str, cwd: &str, path: Option<&str>) -> Vec<(String, Option<String>)> {
        let Ok(cmds) = crate::assess::parse(command) else { return Vec::new() };
        let env = crate::marks::ShellEnv { path: path.map(str::to_owned), ..Default::default() };
        let shell = crate::assess::Shell { env: &env, cwd: Path::new(cwd) };
        let mut out: Vec<(String, Option<String>)> = Vec::new();
        for cmd in &cmds {
            let Some(word) = cmd.words.iter().find(|w| !w.text.contains('=') || w.text.starts_with('-')) else { continue };
            if word.var || word.subst || word.glob || word.text.is_empty() {
                continue;
            }
            let name = word.text.rsplit('/').next().unwrap_or(&word.text).to_owned();
            if name.is_empty() || name.len() > 200 || out.iter().any(|(n, _)| *n == name) {
                continue;
            }
            let key = (word.text.clone(), if word.text.contains('/') { Some(cwd.to_owned()) } else { path.map(str::to_owned) });
            let found = match self.found.get(&key) {
                Some(found) => found.clone(),
                None => {
                    let found = match shell.resolve(&word.text) {
                        Some(crate::assess::Resolved::File(file)) => Some(file.to_string_lossy().into_owned()),
                        _ => None,
                    };
                    if self.found.len() > 10_000 {
                        self.found.clear();
                    }
                    self.found.insert(key, found.clone());
                    found
                }
            };
            out.push((name, found));
            if out.len() >= PROGRAMS_MAX {
                break;
            }
        }
        out
    }
}

/// The repository's `origin` (or first) remote, without credentials.
fn remote(root: &Path) -> Option<String> {
    let dot_git = root.join(".git");
    let config = if dot_git.is_file() {
        // A worktree or submodule: `gitdir: <path>`; its config is in the common folder.
        let text = std::fs::read_to_string(&dot_git).ok()?;
        let target = PathBuf::from(text.trim().strip_prefix("gitdir:")?.trim());
        let target = if target.is_absolute() { target } else { root.join(target) };
        let common = std::fs::read_to_string(target.join("commondir")).ok().map(|c| target.join(c.trim())).unwrap_or(target);
        common.join("config")
    } else {
        dot_git.join("config")
    };
    let text = std::fs::read_to_string(config).ok()?;
    let mut section = String::new();
    let mut first: Option<String> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            section = line.to_owned();
        } else if section.starts_with("[remote ")
            && let Some(url) = line.strip_prefix("url").map(str::trim_start).and_then(|rest| rest.strip_prefix('=')).map(str::trim)
        {
            let url = strip_credentials(url);
            if section == "[remote \"origin\"]" {
                return Some(url);
            }
            first.get_or_insert(url);
        }
    }
    first
}

fn strip_credentials(url: &str) -> String {
    if let Some((scheme, rest)) = url.split_once("://")
        && let Some((auth, host)) = rest.split_once('@')
        && !auth.contains('/')
    {
        return format!("{scheme}://{host}");
    }
    url.to_owned()
}

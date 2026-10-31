//! `cc-terminal`: PTY terminals for the CortexTerm `terminal@1` contract.
//!
//! The shells belong to `cortexd` ([`daemon`]), a small daemon in its own session, so they
//! survive the window closing, the app quitting and plugin swaps. The plugin is its client
//! ([`client`], [`wire`]): it decides how each shell starts, receives the output (already
//! coalesced to about 16 ms) and publishes it as `terminal.output` events; snapshots come from the
//! daemon's VT emulator. When an instance starts serving (`activate`) it takes the terminals
//! over: `terminal.list` shows the same `term_id`s, alive, and `terminal.snapshot` repaints them.
//!
//! zsh, bash 4.4+ and fish start with the shell integration ([`shell`]); its marks are read here
//! ([`marks`]) into the terminal's state and its Runs, which the Run store keeps in the memory
//! plugin's graph and streams ([`store`]; an earlier version's files are imported once, [`migrate`]).
//! What the tracker must not forget (the nonce, the folder, the Run in progress, the PATH and
//! aliases) is kept with the terminal in the daemon and resumed by the next instance; output
//! produced while no instance was attached (the last MiB) is replayed to it for the Runs, not
//! published (the screen already shows it). `terminal.assess` and `terminal.complete` use the
//! terminal's folder, PATH and aliases ([`assess`], [`complete`]); `terminal.file.*` serve the
//! native editor ([`files`]); `terminal.habits` and the learning into memory are [`habits`]. The
//! command service other apps on this machine use through the mesh (`terminal.command.*`) is
//! [`command`]. The paste guard is [`threat`] (`terminal.scan`, and part of `terminal.assess`);
//! what it looks up on the network is [`lookup`] (`terminal.script.fetch`,
//! `terminal.packages.check`); `terminal.sandbox.wrap` runs a script in the sandbox without the
//! person's secrets ([`command::sandboxed_command`]).

pub mod assess;
pub mod client;
pub mod command;
pub mod complete;
pub mod daemon;
pub mod edit;
pub mod files;
pub mod habits;
pub mod keychain;
pub mod logs;
pub mod lookup;
pub mod marks;
pub mod migrate;
pub mod probe;
mod screen;
pub mod shell;
pub mod store;
pub mod threat;
pub mod wire;

use base64::Engine;
use cc_protocol::contracts::terminal::{
    AskAnswerParams, AskForgetParams, AssessParams, Assessment, CompleteParams, Completions, ExitEvent, Habits, HabitsParams, HistogramParams, ListResult,
    OpenParams, OutputEvent, Place, PlaceList, ResizeParams, RunList, RunOutputParams, RunsParams, SandboxParams, Sandboxed, ScanParams, ScanResult,
    ScriptFetchParams, Snapshot, SnapshotParams, StateParams, TermInfo, TermParams, TermState, WriteParams, topics,
};
use cc_protocol::{RpcError, codes, to_value};
use client::Daemon;
use habits::Learner;
use marks::{Saved, Tracker};
use store::{ShellInfo, Store};
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, Weak};
use std::time::Duration;
use wire::{Message, Op, Record, Spawn, Tty};

/// Largest screen accepted. The emulator allocates every cell up front, so an absurd size from a
/// caller (e.g. 65535x65535, four billion cells) would exhaust memory instead of drawing anything.
const MAX_CELLS: u32 = 4_000_000;

/// Publishes an event (topic, data). The plugin routes this to the frame.
pub type Emit = Arc<dyn Fn(&str, Value) + Send + Sync>;

pub fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    match mutex.lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// How the shell ended.
#[derive(Debug, Clone, PartialEq)]
pub struct Exit {
    pub code: i32,
    pub signal: Option<String>,
}

struct Term {
    id: String,
    cwd: String,
    shell: String,
    pid: AtomicU32,
    size: Mutex<(u16, u16)>,
    exit: Mutex<Option<Exit>>,
    tracker: Mutex<Tracker>,
    seq: AtomicU64,
    /// [`Tracker::saved_key`] as last sent to the daemon.
    saved: Mutex<String>,
}

impl Term {
    fn info(&self) -> TermInfo {
        let (cols, rows) = *lock(&self.size);
        let exit = lock(&self.exit).clone();
        TermInfo {
            term_id: self.id.clone(),
            cwd: self.cwd.clone(),
            pid: self.pid.load(Ordering::SeqCst),
            cols,
            rows,
            alive: exit.is_none(),
            shell: self.shell.clone(),
            exit_code: exit.map(|e| e.code),
        }
    }
}

/// The user's login shell: `$SHELL` when it is executable, else the passwd entry, else `/bin/sh`.
pub fn login_shell() -> String {
    if let Ok(shell) = std::env::var("SHELL")
        && is_executable(Path::new(&shell))
    {
        return shell;
    }
    // SAFETY: getpwuid returns a pointer into static storage or null; we copy the string at once.
    let from_passwd = unsafe {
        let entry = libc::getpwuid(libc::getuid());
        if entry.is_null() || (*entry).pw_shell.is_null() {
            None
        } else {
            Some(std::ffi::CStr::from_ptr((*entry).pw_shell).to_string_lossy().into_owned())
        }
    };
    match from_passwd {
        Some(shell) if is_executable(Path::new(&shell)) => shell,
        _ => "/bin/sh".into(),
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    path.is_absolute() && std::fs::metadata(path).map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0).unwrap_or(false)
}

fn no_store() -> RpcError {
    RpcError::new(codes::UNAVAILABLE, "the run store is not available")
}

/// `~`, `~/x` and an empty folder to the home folder.
fn home_cwd(cwd: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    if cwd.trim().is_empty() || cwd == "~" {
        home
    } else if let Some(rest) = cwd.strip_prefix("~/") {
        Path::new(&home).join(rest).to_string_lossy().into_owned()
    } else {
        cwd.to_owned()
    }
}

fn not_found(term_id: &str) -> RpcError {
    RpcError::new(codes::NOT_FOUND, format!("no terminal `{term_id}`"))
}

fn daemon_error(error: String) -> RpcError {
    if error.starts_with("no terminal") {
        RpcError::new(codes::NOT_FOUND, error)
    } else if error.contains("has exited") || error.contains("is closed") {
        RpcError::new(codes::CONFLICT, error)
    } else if error.contains("must be at least") || error.contains("exceeds") {
        RpcError::invalid_params(error)
    } else {
        RpcError::new(codes::UNAVAILABLE, format!("cortexd: {error}"))
    }
}

fn check_size(cols: u16, rows: u16) -> Result<(), RpcError> {
    if cols == 0 || rows == 0 {
        return Err(RpcError::invalid_params("cols and rows must be at least 1"));
    }
    if u32::from(cols) * u32::from(rows) > MAX_CELLS {
        return Err(RpcError::invalid_params(format!("{cols}x{rows} exceeds {MAX_CELLS} cells")));
    }
    Ok(())
}

/// The environment a new shell gets: this process's, without the plugin plumbing (CORTEX_HOME
/// stays, so `cx` finds the frame), with the terminal's own variables.
fn shell_env(cwd: &Path, extra: &[(String, String)]) -> Vec<(String, String)> {
    const PLUMBING: &[&str] = &["CORTEX_FRAME_SOCKET", "CORTEX_PLUGIN_INSTANCE", "CORTEX_PLUGIN_DATA", "CORTEX_LOG"];
    let own = [
        ("TERM", "xterm-256color".to_owned()),
        ("COLORTERM", "truecolor".to_owned()),
        ("TERM_PROGRAM", "CortexTerm".to_owned()),
        ("PWD", cwd.to_string_lossy().into_owned()),
    ];
    let mut env: Vec<(String, String)> = std::env::vars()
        .filter(|(key, _)| !PLUMBING.contains(&key.as_str()) && !own.iter().any(|(k, _)| k == key) && !extra.iter().any(|(k, _)| k == key))
        .collect();
    env.extend(own.into_iter().map(|(k, v)| (k.to_owned(), v)));
    env.extend(extra.iter().cloned());
    env
}

/// All terminals of one plugin instance, served by `cortexd`.
pub struct Terminals {
    me: Weak<Terminals>,
    terms: Mutex<HashMap<String, Arc<Term>>>,
    emit: Emit,
    store: Option<Arc<Store>>,
    home: PathBuf,
    /// The probe's terminals: private to its connection, closed with it.
    guest: bool,
    daemon: Mutex<Option<Arc<Daemon>>>,
    connecting: tokio::sync::Mutex<()>,
    /// This instance no longer serves terminals (a newer one took them over, or it shut down).
    retired: AtomicBool,
    learner: OnceLock<Arc<Learner>>,
}

impl Terminals {
    /// The terminals of the instance that serves the category; Runs go into `store`.
    pub fn new(emit: Emit, store: Option<Arc<Store>>) -> Arc<Self> {
        Self::build(emit, store, false)
    }

    /// The probe's own terminals (Runs not recorded); they never touch the served ones.
    pub fn guest(emit: Emit) -> Arc<Self> {
        Self::build(emit, None, true)
    }

    fn build(emit: Emit, store: Option<Arc<Store>>, guest: bool) -> Arc<Self> {
        Arc::new_cyclic(|me| Self {
            me: me.clone(),
            terms: Mutex::new(HashMap::new()),
            emit,
            store,
            home: wire::home(),
            guest,
            daemon: Mutex::new(None),
            connecting: tokio::sync::Mutex::new(()),
            retired: AtomicBool::new(false),
            learner: OnceLock::new(),
        })
    }

    /// Learn habits into memory from the Runs that finish here.
    pub fn set_learner(&self, learner: Arc<Learner>) {
        let _ = self.learner.set(learner);
    }

    fn store(&self) -> Result<&Arc<Store>, RpcError> {
        self.store.as_ref().ok_or_else(no_store)
    }

    fn get(&self, term_id: &str) -> Result<Arc<Term>, RpcError> {
        if self.retired.load(Ordering::SeqCst) {
            return Err(RpcError::new(codes::UNAVAILABLE, "this terminal plugin instance no longer serves terminals"));
        }
        lock(&self.terms).get(term_id).cloned().ok_or_else(|| not_found(term_id))
    }

    fn emit_all(&self, events: Vec<(&'static str, Value)>) {
        for (topic, data) in events {
            if topic == topics::RUN_FINISHED
                && let Some(learner) = self.learner.get()
            {
                learner.touch(data.get("cwd").and_then(Value::as_str).unwrap_or(""));
            }
            (self.emit)(topic, data);
        }
    }

    fn emit_exit(&self, term_id: &str, exit: &Exit) {
        let event = ExitEvent { term_id: term_id.to_owned(), exit_code: exit.code, signal: exit.signal.clone() };
        if let Ok(value) = serde_json::to_value(&event) {
            (self.emit)(topics::EXIT, value);
        }
    }

    /// The daemon connection, made (and the terminals taken over) on first use.
    async fn daemon(&self) -> Result<Arc<Daemon>, RpcError> {
        if self.retired.load(Ordering::SeqCst) {
            return Err(RpcError::new(codes::UNAVAILABLE, "this terminal plugin instance no longer serves terminals"));
        }
        if let Some(daemon) = lock(&self.daemon).clone() {
            return Ok(daemon);
        }
        let _connecting = self.connecting.lock().await;
        if let Some(daemon) = lock(&self.daemon).clone() {
            return Ok(daemon);
        }
        let me = self.me.clone();
        let on_message = Arc::new(move |message: Option<Message>| {
            if let Some(terms) = me.upgrade() {
                terms.message(message);
            }
        });
        let (daemon, hello) = Daemon::connect(&self.home, self.guest, on_message).await.map_err(daemon_error)?;
        *lock(&self.daemon) = Some(daemon.clone());
        if !self.guest {
            self.adopt(&daemon, hello.terms).await;
            daemon.call::<Value>(Op::Attach).await.map_err(daemon_error)?;
            tracing::info!(pid = daemon.pid, version = daemon.version, terminals = lock(&self.terms).len(), "attached to cortexd");
        }
        if let Some(me) = self.me.upgrade() {
            tokio::spawn(tick(Arc::downgrade(&me)));
        }
        Ok(daemon)
    }

    /// Take over the terminals the daemon already runs (after a restart or a swap). Shells that
    /// ended while nobody was attached are finished and forgotten; the UI starts them again.
    async fn adopt(&self, daemon: &Arc<Daemon>, records: Vec<Record>) {
        for record in records {
            let saved: Saved = serde_json::from_value(record.meta.clone()).unwrap_or_default();
            // The Run in progress, as the previous instance kept it (or as the graph has it), with
            // the lines its output stream holds.
            let mut running = None;
            if let (Some(id), Some(store)) = (saved.running.clone(), self.store.as_ref()) {
                running = match saved.run.clone().filter(|run| run.id == id) {
                    Some(run) => Some(run),
                    None => store.get(&id).await.ok(),
                };
                if let Some(run) = running.as_mut()
                    && let Ok(lines) = store.stored_lines(&id).await
                {
                    run.lines = run.lines.max(lines);
                }
            }
            if let Some(store) = &self.store {
                store.shell(&record.term_id, ShellInfo { shell: record.shell.clone(), started_ms: None, session: saved.session.clone() });
            }
            let tracker = Tracker::resume(
                &record.term_id,
                Saved { cwd: if saved.cwd.is_empty() { record.cwd.clone() } else { saved.cwd.clone() }, ..saved },
                self.store.clone(),
                running,
            );
            let term = Arc::new(Term {
                id: record.term_id.clone(),
                cwd: record.cwd.clone(),
                shell: record.shell.clone(),
                pid: AtomicU32::new(record.pid),
                size: Mutex::new((record.cols, record.rows)),
                exit: Mutex::new(None),
                saved: Mutex::new(tracker.saved_key()),
                tracker: Mutex::new(tracker),
                seq: AtomicU64::new(0),
            });
            if record.alive {
                lock(&self.terms).insert(record.term_id, term);
            } else {
                let events = lock(&term.tracker).end();
                self.emit_all(events);
                let _ = daemon.call::<Value>(Op::Close { term_id: record.term_id }).await;
            }
        }
    }

    /// A message from the daemon (None: the connection ended).
    fn message(&self, message: Option<Message>) {
        match message {
            Some(Message::Output { term_id, data, replay, offset, tty }) => {
                let Ok(term) = self.get(&term_id) else { return };
                let bytes = base64::engine::general_purpose::STANDARD.decode(&data).unwrap_or_default();
                let events = {
                    let mut tracker = lock(&term.tracker);
                    if let Some(tty) = tty { tracker.set_tty(tty); }
                    tracker.feed(&bytes)
                };
                self.emit_all(events);
                if !replay {
                    let seq = term.seq.fetch_add(1, Ordering::SeqCst) + 1;
                    if let Ok(value) = serde_json::to_value(OutputEvent { term_id, data, seq, offset }) {
                        (self.emit)(topics::OUTPUT, value);
                    }
                }
                self.save(&term);
            }
            Some(Message::Exit { term_id, code, signal }) => {
                let exit = Exit { code, signal };
                if let Ok(term) = self.get(&term_id) {
                    self.ended(&term, exit.clone());
                }
                self.emit_exit(&term_id, &exit);
            }
            Some(Message::Taken) => {
                self.retired.store(true, Ordering::SeqCst);
                lock(&self.daemon).take();
                lock(&self.terms).clear();
                tracing::info!("another terminal plugin instance took the terminals over");
            }
            Some(Message::Reply { .. }) => {}
            None => {
                lock(&self.daemon).take();
                if self.retired.load(Ordering::SeqCst) {
                    return;
                }
                // The daemon is gone, and its shells with it.
                tracing::warn!("lost the connection to cortexd; its terminals are gone");
                let terms: Vec<Arc<Term>> = lock(&self.terms).drain().map(|(_, t)| t).collect();
                for term in terms {
                    let exit = Exit { code: -1, signal: Some("cortexd went away".into()) };
                    if self.ended(&term, exit.clone()) {
                        self.emit_exit(&term.id, &exit);
                    }
                }
            }
        }
    }

    /// Record the shell's end once; returns whether this call recorded it.
    fn ended(&self, term: &Term, exit: Exit) -> bool {
        {
            let mut slot = lock(&term.exit);
            if slot.is_some() {
                return false;
            }
            *slot = Some(exit);
        }
        let events = lock(&term.tracker).end();
        self.emit_all(events);
        true
    }

    /// Keep what the tracker must not forget with the terminal in the daemon, when it changed.
    fn save(&self, term: &Term) {
        let (key, saved) = {
            let tracker = lock(&term.tracker);
            let key = tracker.saved_key();
            if *lock(&term.saved) == key {
                return;
            }
            (key, tracker.saved())
        };
        let Some(daemon) = lock(&self.daemon).clone() else { return };
        let Ok(meta) = serde_json::to_value(&saved) else { return };
        *lock(&term.saved) = key;
        drop(daemon.request(Op::Meta { term_id: term.id.clone(), meta }));
    }

    pub async fn open(&self, params: OpenParams) -> Result<TermInfo, RpcError> {
        check_size(params.cols, params.rows)?;
        let cwd = PathBuf::from(home_cwd(&params.cwd));
        if !cwd.is_absolute() || !cwd.is_dir() {
            return Err(RpcError::invalid_params(format!("cwd `{}` is not an existing absolute directory", params.cwd)));
        }
        let daemon = self.daemon().await?;
        let shell = match params.shell {
            Some(shell) if !shell.is_empty() => shell,
            _ => login_shell(),
        };
        let nonce = uuid::Uuid::new_v4().simple().to_string();
        let injection = shell::inject(&shell, params.args.as_deref(), &nonce);
        let args = match (injection.as_ref().and_then(|i| i.args.clone()), params.args) {
            (Some(args), _) | (None, Some(args)) => args,
            (None, None) => vec!["-l".to_owned()],
        };
        let extra = injection.map(|i| i.env).unwrap_or_default();
        let id = format!("term-{}", uuid::Uuid::new_v4().simple());
        let cwd_text = cwd.to_string_lossy().into_owned();
        let session = params.session_id.clone().filter(|s| !s.is_empty());
        if let Some(store) = &self.store {
            store.shell(&id, ShellInfo { shell: shell.clone(), started_ms: Some(marks::now_ms()), session: session.clone() });
        }
        let mut tracker = Tracker::new(&id, &cwd_text, nonce, self.store.clone());
        tracker.session = session;
        let saved = tracker.saved();
        let term = Arc::new(Term {
            id: id.clone(),
            cwd: cwd_text.clone(),
            shell: shell.clone(),
            pid: AtomicU32::new(0),
            size: Mutex::new((params.cols, params.rows)),
            exit: Mutex::new(None),
            saved: Mutex::new(tracker.saved_key()),
            tracker: Mutex::new(tracker),
            seq: AtomicU64::new(0),
        });
        // Known before the daemon starts the shell, so its first output finds the terminal.
        lock(&self.terms).insert(id.clone(), term.clone());
        let spawn = Spawn {
            term_id: id.clone(),
            shell,
            args,
            cwd: cwd_text,
            env: shell_env(&cwd, &extra),
            cols: params.cols,
            rows: params.rows,
            meta: serde_json::to_value(&saved).unwrap_or(Value::Null),
        };
        match daemon.call::<Record>(Op::Open { spawn }).await {
            Ok(record) if record.term_id == id => {
                term.pid.store(record.pid, Ordering::SeqCst);
                Ok(term.info())
            }
            Ok(record) => {
                lock(&self.terms).remove(&id);
                let _ = daemon.call::<Value>(Op::Close { term_id: record.term_id }).await;
                Err(RpcError::internal("cortexd gave the terminal another id"))
            }
            Err(error) => {
                lock(&self.terms).remove(&id);
                Err(daemon_error(error))
            }
        }
    }

    pub async fn write(&self, params: WriteParams) -> Result<(), RpcError> {
        let term = self.get(&params.term_id)?;
        if lock(&term.exit).is_some() {
            return Err(RpcError::new(codes::CONFLICT, format!("terminal `{}` has exited", params.term_id)));
        }
        let typed = lock(&term.tracker).typed();
        self.emit_all(typed);
        let connected = lock(&self.daemon).clone();
        let daemon = match connected {
            Some(daemon) => daemon,
            None => self.daemon().await?,
        };
        // Queued here, before any await: keystrokes reach the shell in the order they came.
        let data = if params.base64 {
            // Validate before queueing; the daemon receives exactly the original bytes.
            base64::engine::general_purpose::STANDARD.decode(&params.data)
                .map_err(|_| RpcError::invalid_params("terminal input is not valid base64"))?;
            params.data
        } else {
            base64::engine::general_purpose::STANDARD.encode(params.data.as_bytes())
        };
        let answer = daemon.request(Op::Write { term_id: params.term_id, data });
        Daemon::answer::<Value>(answer).await.map(|_| ()).map_err(daemon_error)
    }

    pub async fn resize(&self, params: ResizeParams) -> Result<TermInfo, RpcError> {
        check_size(params.cols, params.rows)?;
        let term = self.get(&params.term_id)?;
        let daemon = self.daemon().await?;
        let record: Record = daemon
            .call(Op::Resize { term_id: params.term_id, cols: params.cols, rows: params.rows })
            .await
            .map_err(daemon_error)?;
        *lock(&term.size) = (record.cols, record.rows);
        Ok(term.info())
    }

    /// Hang up the shell's process group and the foreground job (in the daemon), kill whatever
    /// ignored it, forget the terminal.
    pub async fn close(&self, term_id: &str) -> Result<TermInfo, RpcError> {
        let term = self.get(term_id)?;
        let daemon = self.daemon().await?;
        let result = daemon.call::<Record>(Op::Close { term_id: term_id.to_owned() }).await;
        lock(&self.terms).remove(term_id);
        match result {
            Ok(record) => {
                self.ended(&term, Exit { code: record.exit_code.unwrap_or(-1), signal: record.signal });
            }
            Err(error) if error.starts_with("no terminal") => {
                self.ended(&term, Exit { code: -1, signal: None });
            }
            Err(error) => return Err(daemon_error(error)),
        }
        self.upgrade_when_idle(&daemon).await;
        Ok(term.info())
    }

    /// A daemon of another version with no shells left is replaced (see `client`).
    async fn upgrade_when_idle(&self, daemon: &Arc<Daemon>) {
        if self.guest || daemon.version == wire::DAEMON_VERSION || !lock(&self.terms).is_empty() {
            return;
        }
        if daemon.call::<Value>(Op::Quit).await.is_ok() {
            tracing::info!(version = daemon.version, "the old cortexd had no shells left; it quit");
            lock(&self.daemon).take();
        }
    }

    /// Answer what the running command asks; a secret the user wants remembered goes into the
    /// Keychain under the ask's key.
    pub async fn answer(&self, params: AskAnswerParams) -> Result<(), RpcError> {
        let ask = lock(&self.get(&params.term_id)?.tracker).state().ask;
        let secret = params.text.clone();
        self.write(WriteParams { term_id: params.term_id, data: format!("{}\r", params.text), base64: false }).await?;
        if let Some(ask) = ask.filter(|ask| params.remember && ask.kind == "secret" && !secret.is_empty()) {
            run_blocking(move || keychain::set(&ask.key, &secret).map_err(|e| RpcError::new(codes::UNAVAILABLE, e))).await?;
        }
        Ok(())
    }

    /// Remove a remembered secret.
    pub async fn forget(&self, key: String) -> Result<(), RpcError> {
        let gone = key.clone();
        run_blocking(move || keychain::delete(&gone).map_err(|e| RpcError::new(codes::UNAVAILABLE, e))).await?;
        let all: Vec<Arc<Term>> = lock(&self.terms).values().cloned().collect();
        for term in all {
            let events = lock(&term.tracker).forgot(&key);
            self.emit_all(events);
        }
        Ok(())
    }

    /// A password prompt whose answer was remembered: fill it in, once per prompt.
    async fn fill(&self, daemon: &Arc<Daemon>, term: &Arc<Term>) {
        let Some(key) = lock(&term.tracker).fill_wanted() else { return };
        let lookup = key.clone();
        let Ok(Some(secret)) = tokio::task::spawn_blocking(move || keychain::get(&lookup)).await else { return };
        let data = base64::engine::general_purpose::STANDARD.encode(format!("{secret}\r").as_bytes());
        if Daemon::answer::<Value>(daemon.request(Op::Write { term_id: term.id.clone(), data })).await.is_ok() {
            tracing::info!(term = %term.id, %key, "filled a prompt from the Keychain");
            let events = lock(&term.tracker).filled(key);
            self.emit_all(events);
        }
    }

    pub fn list(&self) -> ListResult {
        let mut terminals: Vec<TermInfo> = lock(&self.terms).values().map(|t| t.info()).collect();
        terminals.sort_by(|a, b| a.term_id.cmp(&b.term_id));
        ListResult { terminals }
    }

    pub async fn snapshot(&self, term_id: &str) -> Result<Snapshot, RpcError> {
        self.screen_snapshot(term_id, false).await
    }

    async fn screen_snapshot(&self, term_id: &str, restore: bool) -> Result<Snapshot, RpcError> {
        self.get(term_id)?;
        let daemon = self.daemon().await?;
        let mut snapshot: Snapshot = daemon.call(Op::Snapshot { term_id: term_id.to_owned(), restore }).await.map_err(daemon_error)?;
        // Input is implemented by this plugin, including when an older daemon keeps live shells.
        snapshot.input_base64 = true;
        Ok(snapshot)
    }

    pub fn state(&self, term_id: &str) -> Result<TermState, RpcError> {
        Ok(lock(&self.get(term_id)?.tracker).state())
    }

    /// Recorded Runs, newest first; Runs still in progress carry their live counters.
    pub async fn runs(&self, params: RunsParams) -> Result<RunList, RpcError> {
        let mut runs = self.store()?.runs(&params).await?;
        let live: HashMap<String, cc_protocol::contracts::terminal::Run> = lock(&self.terms)
            .values()
            .filter_map(|t| lock(&t.tracker).running())
            .map(|run| (run.id.clone(), run))
            .collect();
        for run in &mut runs {
            if let Some(current) = live.get(&run.id) {
                *run = current.clone();
            }
        }
        Ok(RunList { runs })
    }

    /// The terminal's folder and what its shell reported about itself.
    fn shell_of(&self, term_id: &str) -> Result<(PathBuf, marks::ShellEnv), RpcError> {
        let term = self.get(term_id)?;
        let tracker = lock(&term.tracker);
        Ok((PathBuf::from(tracker.cwd()), tracker.env.clone()))
    }

    /// What the input would do; a command whose shape (program, subcommand, flags) never ran on
    /// this Mac says so, as a reason (not a threat).
    pub async fn assess(&self, params: AssessParams) -> Result<Assessment, RpcError> {
        let (cwd, env) = self.shell_of(&params.term_id)?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            let mut assessment = assess::assess(&params.input, &assess::Shell { env: &env, cwd: &cwd }, params.pasted);
            if let Some(query) = edit::query(&params.input) {
                let path = edit::path(query);
                // This metadata is for the Line, which opens a file without executing this text.
                // Keep it ineligible for automatic read-only model checks. Command-service risk
                // assessment continues to parse actual shell commands through assess::assess directly.
                assessment.kind = "shell".into();
                assessment.risk = "write".into();
                assessment.safe = false;
                assessment.reasons = vec!["opens CortexTerm editor".into()];
                assessment.program = None;
                assessment.native_view = Some("editor".into());
                assessment.native_target = (!path.is_empty()).then(|| assess::expand(&path, &cwd).to_string_lossy().into_owned());
            }
            if assessment.kind != "ask"
                && let Some(store) = store
                && !store.new_shapes(&assessment.text).is_empty()
            {
                assessment.reasons.push("first time anything like this ran here".into());
            }
            assessment
        })
        .await
        .map_err(|e| RpcError::internal(format!("assess task failed: {e}")))
    }

    /// The command line that runs `command` sandboxed, without access to secrets, in the
    /// terminal's folder.
    pub fn sandbox_wrap(&self, params: SandboxParams) -> Result<Sandboxed, RpcError> {
        let (cwd, _) = self.shell_of(&params.term_id)?;
        command::sandboxed_command(&self.home, &cwd, &params.command)
            .map(|command| Sandboxed { command })
            .map_err(|e| RpcError::new(codes::UNAVAILABLE, e))
    }

    pub async fn complete(&self, params: CompleteParams) -> Result<Completions, RpcError> {
        let (cwd, env) = self.shell_of(&params.term_id)?;
        let store = self.store.clone();
        tokio::task::spawn_blocking(move || {
            if edit::query(&params.line).is_some() {
                return edit::complete(&params.line, &cwd);
            }
            let cursor = params.cursor as usize;
            let suggestion = match &store {
                Some(store) if cursor >= params.line.len() && !params.line.trim().is_empty() => {
                    store.suggestion(&params.line, &cwd.to_string_lossy(), &params.term_id)
                }
                _ => None,
            };
            Ok(complete::complete(&params.line, cursor, &assess::Shell { env: &env, cwd: &cwd }, suggestion))
        })
        .await
        .map_err(|e| RpcError::internal(format!("complete task failed: {e}")))?
    }

    /// What CortexTerm knows about a folder: the commands used there and above it, and what was
    /// learned into memory about it.
    pub async fn habits(&self, params: HabitsParams) -> Result<Habits, RpcError> {
        let cwd = home_cwd(&params.cwd);
        let cwd = cwd.trim_end_matches('/').to_owned();
        let cwd = if cwd.is_empty() { "/".to_owned() } else { cwd };
        let limit = if params.limit == 0 { 8 } else { params.limit };
        let folders = habits::scope(&cwd);
        let habits = self.store()?.habits(&folders, limit).await?;
        let notes = match self.learner.get() {
            Some(learner) => learner.notes(&cwd).await.unwrap_or_else(|error| {
                tracing::debug!("habits: memory has no notes for {cwd}: {error}");
                Vec::new()
            }),
            None => Vec::new(),
        };
        Ok(Habits { cwd, habits, notes })
    }

    /// Folders the Runs happened in, most used first, then the folders known from memory.
    pub async fn places(&self, limit: u32) -> Result<PlaceList, RpcError> {
        let limit = if limit == 0 { 50 } else { limit.min(1000) };
        let mut places = self.store()?.places(limit).await?;
        if places.len() < limit as usize
            && let Some(learner) = self.learner.get()
            && let Ok(mut known) = learner.places().await
        {
            known.sort_by(|a, b| b.1.cmp(&a.1));
            for (path, last) in known {
                if places.len() >= limit as usize {
                    break;
                }
                if !places.iter().any(|p| p.path == path) && Path::new(&path).is_dir() {
                    let git = store::in_git(Path::new(&path));
                    places.push(Place { path, runs: 0, last, git });
                }
            }
        }
        Ok(PlaceList { places })
    }

    /// Take the daemon's terminals over now (the instance starts serving).
    pub async fn attach(&self) -> Result<(), RpcError> {
        self.daemon().await.map(|_| ())
    }

    /// Stop serving without touching the shells: they keep running in the daemon for the next
    /// instance (plugin shutdown, the app quitting).
    pub fn detach(&self) {
        self.retired.store(true, Ordering::SeqCst);
        lock(&self.daemon).take();
    }

    /// Close every terminal of this instance (the probe's).
    pub async fn close_all(&self) {
        let ids: Vec<String> = lock(&self.terms).keys().cloned().collect();
        for id in ids {
            let _ = self.close(&id).await;
        }
    }

    /// Serve one `terminal.*` method.
    pub async fn dispatch(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        use cc_protocol::contracts::terminal::methods;
        use cc_protocol::parse_params;
        match method {
            methods::OPEN => to_value(&self.open(parse_params(params)?).await?),
            methods::WRITE => {
                self.write(parse_params(params)?).await?;
                Ok(Value::Null)
            }
            methods::RESIZE => to_value(&self.resize(parse_params(params)?).await?),
            methods::CLOSE => {
                let p: TermParams = parse_params(params)?;
                to_value(&self.close(&p.term_id).await?)
            }
            methods::LIST => to_value(&self.list()),
            methods::SNAPSHOT => {
                let p: SnapshotParams = parse_params(params)?;
                to_value(&self.screen_snapshot(&p.term_id, p.restore).await?)
            }
            methods::STATE => {
                let p: StateParams = parse_params(params)?;
                to_value(&self.state(&p.term_id)?)
            }
            methods::RUNS => to_value(&self.runs(parse_params(params)?).await?),
            methods::RUN_OUTPUT => {
                let p: RunOutputParams = parse_params(params)?;
                to_value(&self.store()?.output(&p).await?)
            }
            methods::RUN_HISTOGRAM => {
                let p: HistogramParams = parse_params(params)?;
                to_value(&self.store()?.histogram(&p.run_id, p.buckets).await?)
            }
            methods::PLACES => {
                let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(0).min(u64::from(u32::MAX)) as u32;
                to_value(&self.places(limit).await?)
            }
            methods::HABITS => to_value(&self.habits(parse_params(params)?).await?),
            methods::ASK_ANSWER => {
                self.answer(parse_params(params)?).await?;
                Ok(Value::Null)
            }
            methods::ASK_FORGET => {
                let p: AskForgetParams = parse_params(params)?;
                self.forget(p.key).await?;
                Ok(Value::Null)
            }
            methods::ASSESS => to_value(&self.assess(parse_params(params)?).await?),
            methods::SCAN => {
                let p: ScanParams = parse_params(params)?;
                to_value(&ScanResult { threats: run_blocking(move || Ok(threat::scan(&p.text, p.pasted))).await? })
            }
            methods::SCRIPT_FETCH => {
                let p: ScriptFetchParams = parse_params(params)?;
                to_value(&lookup::fetch_script(&p.url).await.map_err(|e| RpcError::new(codes::UNAVAILABLE, e))?)
            }
            methods::PACKAGES_CHECK => {
                let p: ScanParams = parse_params(params)?;
                to_value(&lookup::check_packages(&p.text).await)
            }
            methods::SANDBOX_WRAP => to_value(&self.sandbox_wrap(parse_params(params)?)?),
            methods::COMPLETE => to_value(&self.complete(parse_params(params)?).await?),
            methods::FILE_READ => {
                let p = parse_params(params)?;
                to_value(&run_blocking(move || files::read(p)).await?)
            }
            methods::FILE_WRITE => {
                let p = parse_params(params)?;
                to_value(&run_blocking(move || files::write(p)).await?)
            }
            other => Err(RpcError::unknown_method(other)),
        }
    }
}

async fn run_blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T, RpcError> + Send + 'static) -> Result<T, RpcError> {
    tokio::task::spawn_blocking(work).await.map_err(|e| RpcError::internal(format!("task failed: {e}")))?
}

/// Re-evaluate time-based attention (a quiet command waits for input) while connected: a quiet
/// command's terminal echo is read (a password prompt turns it off), and a prompt whose secret
/// was remembered is filled in.
async fn tick(terms: Weak<Terminals>) {
    let mut interval = tokio::time::interval(Duration::from_millis(500));
    loop {
        interval.tick().await;
        let Some(terms) = terms.upgrade() else { break };
        let Some(daemon) = lock(&terms.daemon).clone() else { break };
        let all: Vec<Arc<Term>> = lock(&terms.terms).values().cloned().collect();
        for term in all {
            // An older daemon has no `tty` (and would not answer it); the prompt's words decide.
            let reads_tty = daemon.version >= 2;
            lock(&term.tracker).set_reads_tty(reads_tty);
            if reads_tty
                && lock(&term.tracker).wants_tty(marks::now_ms())
                && let Ok(tty) = daemon.call::<Tty>(Op::Tty { term_id: term.id.clone() }).await
            {
                lock(&term.tracker).set_tty(tty);
            }
            let events = lock(&term.tracker).tick();
            terms.emit_all(events);
            terms.save(&term);
            if !terms.guest {
                terms.fill(&daemon, &term).await;
            }
        }
    }
}

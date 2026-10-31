//! `cortexd`: the PTY daemon that owns the shells, so they outlive the window, the app and plugin
//! swaps. The terminal plugin is its client (see `client` and `wire`).
//!
//! Each terminal is a shell on its own pseudo-terminal with three threads: a reader that feeds the
//! VT emulator (`vt100`, for snapshots) and queues the bytes for the owner, a writer that writes
//! queued input in order, and a waiter that records the exit. A sender task per terminal ships the
//! queue to the owning connection, coalescing what arrives within about 16 ms into one message.
//!
//! Flow control: while an owner is attached, the reader stops when more than 1 MiB is unsent
//! (queued, or written to the socket but not yet taken by the client) and resumes below 256 KiB.
//! With no owner, the shell keeps running and the screen stays current; the last 1 MiB of output
//! is kept and replayed to the next owner (flagged `replay`), so the plugin can finish the Runs
//! that were in progress.
//!
//! The daemon leads its own session (it is not one of the frame's children and is not stopped
//! with the app) and exits by itself after ten minutes with no living shell and no client.

use crate::wire::{self, Hello, Message, Op, Record, Request, Spawn, Tty};
use base64::Engine;
use cc_protocol::contracts::terminal::Snapshot;
use portable_pty::{ChildKiller, CommandBuilder, MasterPty, PtySize, native_pty_system};
use serde_json::Value;
use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Notify, mpsc};

use crate::lock;
use crate::screen::ScreenState;

/// Output arriving within this window goes into one message.
const COALESCE: Duration = Duration::from_millis(16);
/// Stop reading a shell above this much unsent output (and keep at most this much with no owner).
const HIGH: usize = 1 << 20;
/// Resume reading below this.
const LOW: usize = 256 << 10;
/// How long a hung-up shell gets to exit before it is killed.
const HANGUP_GRACE: Duration = Duration::from_millis(1500);
/// After the shell exits, how long the reader may still drain its last words.
const EXIT_GRACE: Duration = Duration::from_millis(150);
/// Exit after this long with no living shell and no client.
const IDLE_EXIT: Duration = Duration::from_secs(600);
/// Largest screen accepted (the emulator allocates every cell up front).
const MAX_CELLS: u32 = 4_000_000;

#[derive(Debug, Clone)]
struct Exit {
    code: i32,
    signal: Option<String>,
}

/// What goes to a client: one line, and the output bytes it carries (credited back to the
/// terminal once written).
struct Outgoing {
    line: String,
    credit: Option<(Arc<Term>, u64, usize)>,
}

struct Client {
    id: u64,
    guest: bool,
    tx: mpsc::UnboundedSender<Outgoing>,
    kicked: Notify,
}

impl Client {
    fn send(&self, message: &Message) {
        if let Ok(line) = serde_json::to_string(message) {
            let _ = self.tx.send(Outgoing { line, credit: None });
        }
    }
}

#[derive(Default)]
struct Flow {
    pending: Vec<u8>,
    /// Exclusive offset of the last byte queued, including bytes discarded with no owner.
    offset: u64,
    /// The first `replay` bytes of `pending` were produced while no owner was attached.
    replay: usize,
    in_flight: usize,
    owner: Option<Arc<Client>>,
    /// Bumped on every owner change, so credits for an earlier owner's bytes are ignored.
    generation: u64,
    reader_done: bool,
    exit: Option<Exit>,
    exit_at: Option<Instant>,
    exit_sent: bool,
    closed: bool,
}

struct Term {
    id: String,
    pid: u32,
    shell: String,
    cwd: String,
    /// The guest connection that opened it (closed with that connection).
    guest: Option<u64>,
    size: Mutex<(u16, u16)>,
    meta: Mutex<Value>,
    master: Mutex<Option<Box<dyn MasterPty + Send>>>,
    input: Mutex<Option<std::sync::mpsc::Sender<Vec<u8>>>>,
    parser: Mutex<ScreenState>,
    killer: Mutex<Box<dyn ChildKiller + Send + Sync>>,
    flow: Mutex<Flow>,
    room: Condvar,
    wake: Notify,
}

impl Term {
    fn record(&self) -> Record {
        let (cols, rows) = *lock(&self.size);
        let exit = lock(&self.flow).exit.clone();
        Record {
            term_id: self.id.clone(),
            pid: self.pid,
            shell: self.shell.clone(),
            cwd: self.cwd.clone(),
            cols,
            rows,
            alive: exit.is_none(),
            exit_code: exit.as_ref().map(|e| e.code),
            signal: exit.and_then(|e| e.signal),
            meta: lock(&self.meta).clone(),
        }
    }

    fn alive(&self) -> bool {
        lock(&self.flow).exit.is_none()
    }

    fn set_owner(&self, owner: Option<Arc<Client>>) {
        let mut flow = lock(&self.flow);
        flow.replay = if owner.is_some() { flow.pending.len() } else { 0 };
        flow.owner = owner;
        flow.generation += 1;
        flow.in_flight = 0;
        drop(flow);
        self.room.notify_all();
        self.wake.notify_one();
    }

    fn credit(&self, generation: u64, bytes: usize) {
        let mut flow = lock(&self.flow);
        if flow.generation == generation {
            flow.in_flight = flow.in_flight.saturating_sub(bytes);
        }
        drop(flow);
        self.room.notify_all();
    }

    /// Ship what is queued to the owner (and the exit, once the last output is out). Returns
    /// whether the sender is done (the terminal was closed).
    fn flush(self: &Arc<Self>) -> bool {
        let engine = base64::engine::general_purpose::STANDARD;
        let tty = self.tty_flags();
        let mut flow = lock(&self.flow);
        let closed = flow.closed;
        let Some(owner) = flow.owner.clone() else { return closed };
        let generation = flow.generation;
        if !flow.pending.is_empty() {
            let bytes = std::mem::take(&mut flow.pending);
            let replay = flow.replay.min(bytes.len());
            flow.replay = 0;
            flow.in_flight += bytes.len();
            let mut offset = flow.offset - bytes.len() as u64;
            for (part, is_replay) in [(&bytes[..replay], true), (&bytes[replay..], false)] {
                if part.is_empty() {
                    continue;
                }
                offset += part.len() as u64;
                let message = Message::Output {
                    term_id: self.id.clone(), data: engine.encode(part), replay: is_replay,
                    offset: Some(offset), tty: Some(tty.clone()),
                };
                if let Ok(line) = serde_json::to_string(&message) {
                    let _ = owner.tx.send(Outgoing { line, credit: Some((self.clone(), generation, part.len())) });
                }
            }
        }
        let drained = flow.closed || flow.reader_done || flow.exit_at.is_some_and(|at| at.elapsed() >= EXIT_GRACE);
        if let Some(exit) = flow.exit.clone()
            && drained
            && !flow.exit_sent
        {
            flow.exit_sent = true;
            owner.send(&Message::Exit { term_id: self.id.clone(), code: exit.code, signal: exit.signal });
        }
        closed
    }

    /// Process groups to signal: the shell's own (a session leader: its pgid is its pid) and the
    /// terminal's foreground group (a running job such as `vim` or `sleep`).
    fn groups(&self) -> Vec<libc::pid_t> {
        let mut groups = Vec::new();
        if let Ok(pid) = libc::pid_t::try_from(self.pid)
            && pid > 0
        {
            groups.push(pid);
        }
        if let Some(master) = lock(&self.master).as_ref()
            && let Some(foreground) = master.process_group_leader()
            && foreground > 0
            && !groups.contains(&foreground)
        {
            groups.push(foreground);
        }
        groups
    }

    /// The PTY's echo and line-mode flags (the slave's, read through the master) and the program
    /// in the foreground.
    fn tty_flags(&self) -> Tty {
        let master = lock(&self.master);
        let Some(master) = master.as_ref() else { return Tty::default() };
        let mut tty = Tty::default();
        if let Some(fd) = master.as_raw_fd() {
            // SAFETY: tcgetattr only fills the struct; fd is the open master.
            unsafe {
                let mut termios: libc::termios = std::mem::zeroed();
                if libc::tcgetattr(fd, &mut termios) == 0 {
                    tty.valid = true;
                    tty.echo = termios.c_lflag & libc::ECHO != 0;
                    tty.canonical = termios.c_lflag & libc::ICANON != 0;
                }
            }
        }
        tty.foreground = master.process_group_leader().is_some_and(|group| group > 0 && group as u32 != self.pid);
        tty
    }

    fn tty(&self) -> Tty {
        let mut tty = self.tty_flags();
        // Only prompt recognition needs a name; don't enumerate all processes for every frame.
        if tty.valid && tty.canonical && !tty.echo
            && let Some(group) = lock(&self.master).as_ref().and_then(|master| master.process_group_leader())
        {
            tty.program = newest_in_group(group);
        }
        tty
    }

    async fn wait_exit(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        while !self.exited() {
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        true
    }

    fn exited(&self) -> bool {
        lock(&self.flow).exit.is_some()
    }

    /// Hang up the shell and its jobs, kill whatever ignored it, release the PTY.
    async fn close(&self) {
        let sid = libc::pid_t::try_from(self.pid).unwrap_or(0);
        if !self.exited() || !session_members(sid).is_empty() {
            let groups = self.groups();
            signal(&groups, libc::SIGHUP);
            let deadline = Instant::now() + HANGUP_GRACE;
            while Instant::now() < deadline && (!self.exited() || !session_members(sid).is_empty()) {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            let remaining = session_members(sid);
            if !self.exited() || !remaining.is_empty() {
                signal(&groups, libc::SIGKILL);
                for pid in remaining {
                    // SAFETY: plain syscall on a pid that belongs to this terminal's session.
                    unsafe {
                        libc::kill(pid, libc::SIGKILL);
                    }
                }
                let _ = lock(&self.killer).kill();
                self.wait_exit(Duration::from_secs(5)).await;
            }
        }
        lock(&self.input).take();
        lock(&self.master).take();
        lock(&self.flow).closed = true;
        self.room.notify_all();
        self.wake.notify_one();
    }
}

/// Processes whose session is `sid` (members keep it after the leader exits). Processes that
/// started their own session (daemons, `setsid`) left the terminal and are not included.
fn session_members(sid: libc::pid_t) -> Vec<libc::pid_t> {
    if sid <= 0 {
        return Vec::new();
    }
    all_pids()
        .into_iter()
        // SAFETY: getsid only reads kernel process state.
        .filter(|pid| *pid > 0 && unsafe { libc::getsid(*pid) } == sid)
        .collect()
}

#[cfg(target_os = "macos")]
fn all_pids() -> Vec<libc::pid_t> {
    // SAFETY: proc_listallpids fills at most `buffersize` bytes and returns the number of pids.
    unsafe {
        let count = libc::proc_listallpids(std::ptr::null_mut(), 0);
        if count <= 0 {
            return Vec::new();
        }
        let mut pids: Vec<libc::pid_t> = vec![0; count as usize + 256];
        let bytes = (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int;
        let filled = libc::proc_listallpids(pids.as_mut_ptr().cast(), bytes);
        pids.truncate(filled.max(0) as usize);
        pids
    }
}

#[cfg(not(target_os = "macos"))]
fn all_pids() -> Vec<libc::pid_t> {
    std::fs::read_dir("/proc")
        .map(|entries| {
            entries.flatten().filter_map(|entry| entry.file_name().to_str().and_then(|name| name.parse().ok())).collect()
        })
        .unwrap_or_default()
}

/// The name of the most recently started process in a process group (`brew` runs `sudo`, which
/// asks: `sudo`).
#[cfg(target_os = "macos")]
fn newest_in_group(group: libc::pid_t) -> String {
    let mut newest: Option<((u64, u64), String)> = None;
    for pid in all_pids() {
        // SAFETY: proc_pidinfo fills at most `size` bytes of a plain C struct.
        let info = unsafe {
            let mut info: libc::proc_bsdinfo = std::mem::zeroed();
            let size = std::mem::size_of::<libc::proc_bsdinfo>() as libc::c_int;
            if libc::proc_pidinfo(pid, libc::PROC_PIDTBSDINFO, 0, (&raw mut info).cast(), size) != size {
                continue;
            }
            info
        };
        if info.pbi_pgid as libc::pid_t != group {
            continue;
        }
        let started = (info.pbi_start_tvsec, info.pbi_start_tvusec);
        if newest.as_ref().is_none_or(|(at, _)| started > *at) {
            let comm = if info.pbi_name[0] != 0 { &info.pbi_name[..] } else { &info.pbi_comm[..] };
            // SAFETY: both are NUL-terminated arrays filled by the kernel.
            let name = unsafe { std::ffi::CStr::from_ptr(comm.as_ptr()) }.to_string_lossy().into_owned();
            newest = Some((started, name));
        }
    }
    newest.map(|(_, name)| name).unwrap_or_default()
}

#[cfg(not(target_os = "macos"))]
fn newest_in_group(group: libc::pid_t) -> String {
    std::fs::read_to_string(format!("/proc/{group}/comm")).map(|name| name.trim().to_owned()).unwrap_or_default()
}

fn signal(groups: &[libc::pid_t], signo: libc::c_int) {
    for group in groups {
        // SAFETY: plain syscall; a negative pid addresses the whole process group.
        unsafe {
            libc::kill(-group, signo);
        }
    }
}

fn valid_id(id: &str) -> bool {
    id.starts_with("term-") && id.len() < 80 && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn json<T: serde::Serialize>(value: Result<T, String>) -> Result<Value, String> {
    value.and_then(|v| serde_json::to_value(v).map_err(|e| e.to_string()))
}

fn check_size(cols: u16, rows: u16) -> Result<(), String> {
    if cols == 0 || rows == 0 {
        return Err("cols and rows must be at least 1".into());
    }
    if u32::from(cols) * u32::from(rows) > MAX_CELLS {
        return Err(format!("{cols}x{rows} exceeds {MAX_CELLS} cells"));
    }
    Ok(())
}

struct Daemon {
    terms: Mutex<HashMap<String, Arc<Term>>>,
    owner: Mutex<Option<Arc<Client>>>,
    clients: AtomicUsize,
    next_client: AtomicU64,
    socket: PathBuf,
}

impl Daemon {
    fn get(&self, term_id: &str) -> Result<Arc<Term>, String> {
        lock(&self.terms).get(term_id).cloned().ok_or_else(|| format!("no terminal `{term_id}`"))
    }

    fn visible(&self, client: &Client) -> Vec<Arc<Term>> {
        let mut terms: Vec<Arc<Term>> = lock(&self.terms)
            .values()
            .filter(|t| if client.guest { t.guest == Some(client.id) } else { t.guest.is_none() })
            .cloned()
            .collect();
        terms.sort_by(|a, b| a.id.cmp(&b.id));
        terms
    }

    fn open(&self, client: &Arc<Client>, spawn: Spawn) -> Result<Record, String> {
        check_size(spawn.cols, spawn.rows)?;
        let pair = native_pty_system()
            .openpty(PtySize { rows: spawn.rows, cols: spawn.cols, pixel_width: 0, pixel_height: 0 })
            .map_err(|e| format!("cannot open a pseudo-terminal: {e}"))?;
        let mut command = CommandBuilder::new(&spawn.shell);
        command.args(&spawn.args);
        command.cwd(&spawn.cwd);
        command.env_clear();
        for (key, value) in &spawn.env {
            command.env(key, value);
        }
        let mut child = pair.slave.spawn_command(command).map_err(|e| format!("cannot start `{}`: {e}", spawn.shell))?;
        // Only the shell holds the slave side now; its last close is what ends our reads.
        drop(pair.slave);
        let pid = child.process_id().unwrap_or(0);
        let killer = child.clone_killer();
        let mut reader = pair.master.try_clone_reader().map_err(|e| format!("pty reader: {e}"))?;
        let mut writer = pair.master.take_writer().map_err(|e| format!("pty writer: {e}"))?;
        let id = if valid_id(&spawn.term_id) && !lock(&self.terms).contains_key(&spawn.term_id) {
            spawn.term_id.clone()
        } else {
            format!("term-{}", uuid::Uuid::new_v4().simple())
        };
        let (input_tx, input_rx) = std::sync::mpsc::channel::<Vec<u8>>();
        let owner = if client.guest { Some(client.clone()) } else { lock(&self.owner).clone() };
        let term = Arc::new(Term {
            id: id.clone(),
            pid,
            shell: spawn.shell.clone(),
            cwd: spawn.cwd.clone(),
            guest: client.guest.then_some(client.id),
            size: Mutex::new((spawn.cols, spawn.rows)),
            meta: Mutex::new(spawn.meta),
            master: Mutex::new(Some(pair.master)),
            input: Mutex::new(Some(input_tx)),
            parser: Mutex::new(ScreenState::new(spawn.rows, spawn.cols)),
            killer: Mutex::new(killer),
            flow: Mutex::new(Flow { owner, ..Flow::default() }),
            room: Condvar::new(),
            wake: Notify::new(),
        });

        let reading = term.clone();
        std::thread::Builder::new()
            .name(format!("{id}-read"))
            .spawn(move || {
                let mut buffer = vec![0u8; 64 * 1024];
                loop {
                    match reader.read(&mut buffer) {
                        // EOF, or EIO once the last slave descriptor is closed (macOS and Linux).
                        Ok(0) => break,
                        Ok(n) => {
                            let bytes = &buffer[..n];
                            // The emulator sees bytes before they are sent, so a snapshot taken
                            // after an output message always reflects that output.
                            let mut parser = lock(&reading.parser);
                            parser.process(bytes);
                            let mut flow = lock(&reading.flow);
                            flow.offset = parser.offset;
                            flow.pending.extend_from_slice(bytes);
                            drop(parser);
                            if flow.owner.is_none() && flow.pending.len() > HIGH {
                                let cut = flow.pending.len() - HIGH;
                                flow.pending.drain(..cut);
                            }
                            reading.wake.notify_one();
                            if flow.owner.is_some() && flow.pending.len() + flow.in_flight > HIGH {
                                while flow.owner.is_some() && !flow.closed && flow.pending.len() + flow.in_flight > LOW {
                                    flow = reading.room.wait(flow).unwrap_or_else(|p| p.into_inner());
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
                lock(&reading.flow).reader_done = true;
                reading.wake.notify_one();
            })
            .map_err(|e| format!("cannot start the reader thread: {e}"))?;

        std::thread::Builder::new()
            .name(format!("{id}-write"))
            .spawn(move || {
                while let Ok(data) = input_rx.recv() {
                    if writer.write_all(&data).and_then(|()| writer.flush()).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| format!("cannot start the writer thread: {e}"))?;

        let waiting = term.clone();
        std::thread::Builder::new()
            .name(format!("{id}-wait"))
            .spawn(move || {
                let exit = match child.wait() {
                    Ok(status) => Exit { code: i32::try_from(status.exit_code()).unwrap_or(i32::MAX), signal: status.signal().map(str::to_owned) },
                    Err(error) => Exit { code: -1, signal: Some(format!("wait failed: {error}")) },
                };
                {
                    let mut flow = lock(&waiting.flow);
                    flow.exit = Some(exit);
                    flow.exit_at = Some(Instant::now());
                }
                waiting.wake.notify_one();
                // A background job that keeps the PTY open must not delay the exit message.
                std::thread::sleep(EXIT_GRACE);
                waiting.wake.notify_one();
            })
            .map_err(|e| format!("cannot start the waiter thread: {e}"))?;

        tokio::spawn(sender(term.clone()));
        let record = term.record();
        lock(&self.terms).insert(id, term);
        Ok(record)
    }

    fn write(&self, term_id: &str, data: &str) -> Result<(), String> {
        let term = self.get(term_id)?;
        if !term.alive() {
            return Err(format!("terminal `{term_id}` has exited"));
        }
        let bytes = base64::engine::general_purpose::STANDARD.decode(data).map_err(|e| format!("bad base64: {e}"))?;
        let input = lock(&term.input);
        input.as_ref().ok_or("terminal is closed")?.send(bytes).map_err(|_| "terminal is closed".to_owned())
    }

    fn resize(&self, term_id: &str, cols: u16, rows: u16) -> Result<Record, String> {
        check_size(cols, rows)?;
        let term = self.get(term_id)?;
        // SIGWINCH can trigger a redraw immediately. Hold the parser until its size is updated.
        let mut parser = lock(&term.parser);
        {
            let master = lock(&term.master);
            let master = master.as_ref().ok_or("terminal is closed")?;
            // TIOCSWINSZ on the master; the kernel delivers SIGWINCH to the foreground group.
            master.resize(PtySize { rows, cols, pixel_width: 0, pixel_height: 0 }).map_err(|e| format!("resize failed: {e}"))?;
        }
        parser.set_size(rows, cols);
        *lock(&term.size) = (cols, rows);
        drop(parser);
        Ok(term.record())
    }

    fn snapshot(&self, term_id: &str, restore: bool) -> Result<Snapshot, String> {
        let term = self.get(term_id)?;
        let parser = lock(&term.parser);
        let screen = parser.screen();
        let (cursor_row, cursor_col) = screen.cursor_position();
        let (rows, cols) = screen.size();
        Ok(Snapshot {
            term_id: term_id.to_owned(),
            text: screen.contents(),
            cursor_row,
            cursor_col,
            cols,
            rows,
            alive: term.alive(),
            alternate_screen: screen.alternate_screen(),
            restore: if restore { parser.restore() } else { None },
            input_base64: true,
        })
    }

    async fn close(&self, term_id: &str) -> Result<Record, String> {
        let term = self.get(term_id)?;
        term.close().await;
        lock(&self.terms).remove(term_id);
        Ok(term.record())
    }

    /// `client` owns every (non-guest) terminal from now on; the previous owner is let go.
    fn attach(&self, client: &Arc<Client>) {
        let previous = lock(&self.owner).replace(client.clone());
        for term in self.visible(client) {
            term.set_owner(Some(client.clone()));
        }
        if let Some(previous) = previous
            && previous.id != client.id
        {
            previous.send(&Message::Taken);
            previous.kicked.notify_one();
        }
    }

    /// A connection ended: its guest terminals are closed; the terminals it owned keep running
    /// and queue their output for the next owner.
    async fn disconnect(&self, client: &Arc<Client>) {
        let was_owner = {
            let mut owner = lock(&self.owner);
            let was = owner.as_ref().is_some_and(|o| o.id == client.id);
            if was {
                *owner = None;
            }
            was
        };
        let terms: Vec<Arc<Term>> = lock(&self.terms).values().cloned().collect();
        for term in terms {
            if term.guest == Some(client.id) {
                let _ = self.close(&term.id).await;
            } else if was_owner {
                term.set_owner(None);
            }
        }
    }

    fn living(&self) -> usize {
        lock(&self.terms).values().filter(|t| t.alive()).count()
    }

    async fn handle(self: &Arc<Self>, client: &Arc<Client>, request: Request) {
        let id = request.id;
        let reply = |result: Result<Value, String>| {
            let message = match result {
                Ok(ok) => Message::Reply { id, ok, error: None },
                Err(error) => Message::Reply { id, ok: Value::Null, error: Some(error) },
            };
            client.send(&message);
        };
        match request.op {
            Op::Hello { .. } => reply(json(Ok(Hello {
                version: wire::DAEMON_VERSION,
                pid: std::process::id(),
                terms: self.visible(client).iter().map(|t| t.record()).collect(),
            }))),
            Op::Attach => {
                if client.guest {
                    reply(Err("a guest cannot attach".into()));
                } else {
                    // The reply goes out before any output, so the client knows its terminals first.
                    reply(Ok(Value::Null));
                    self.attach(client);
                }
            }
            Op::Open { spawn } => reply(json(self.open(client, spawn))),
            Op::Write { term_id, data } => reply(self.write(&term_id, &data).map(|()| Value::Null)),
            Op::Resize { term_id, cols, rows } => reply(json(self.resize(&term_id, cols, rows))),
            Op::Snapshot { term_id, restore } => reply(json(self.snapshot(&term_id, restore))),
            Op::Tty { term_id } => reply(json(self.get(&term_id).map(|term| term.tty()))),
            Op::Meta { term_id, meta } => reply(self.get(&term_id).map(|term| {
                *lock(&term.meta) = meta;
                Value::Null
            })),
            Op::Close { term_id } => {
                let daemon = self.clone();
                let client = client.clone();
                // A hang-up takes up to seconds; other requests (input to other panes) go on.
                tokio::spawn(async move {
                    let result = json(daemon.close(&term_id).await);
                    let message = match result {
                        Ok(ok) => Message::Reply { id, ok, error: None },
                        Err(error) => Message::Reply { id, ok: Value::Null, error: Some(error) },
                    };
                    client.send(&message);
                });
            }
            Op::Quit => {
                if self.living() > 0 {
                    reply(Err("shells are still running".into()));
                } else {
                    reply(Ok(Value::Null));
                    let socket = self.socket.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        let _ = std::fs::remove_file(&socket);
                        tracing::info!("cortexd: quitting on request");
                        std::process::exit(0);
                    });
                }
            }
        }
    }

    async fn serve(self: Arc<Self>, stream: UnixStream) {
        let (read, mut write) = stream.into_split();
        let (tx, mut rx) = mpsc::unbounded_channel::<Outgoing>();
        tokio::spawn(async move {
            while let Some(out) = rx.recv().await {
                let mut line = out.line.into_bytes();
                line.push(b'\n');
                if write.write_all(&line).await.is_err() {
                    break;
                }
                if let Some((term, generation, bytes)) = out.credit {
                    term.credit(generation, bytes);
                }
            }
        });
        let mut lines = BufReader::new(read).lines();
        // The first request decides what kind of client this is.
        let first = match lines.next_line().await {
            Ok(Some(line)) => line,
            _ => return,
        };
        let Ok(first) = serde_json::from_str::<Request>(&first) else { return };
        let guest = matches!(first.op, Op::Hello { guest: true });
        let client = Arc::new(Client { id: self.next_client.fetch_add(1, Ordering::SeqCst), guest, tx, kicked: Notify::new() });
        self.clients.fetch_add(1, Ordering::SeqCst);
        self.handle(&client, first).await;
        loop {
            tokio::select! {
                line = lines.next_line() => match line {
                    Ok(Some(line)) => match serde_json::from_str::<Request>(&line) {
                        Ok(request) => self.handle(&client, request).await,
                        Err(error) => tracing::warn!("cortexd: bad request: {error}"),
                    },
                    _ => break,
                },
                () = client.kicked.notified() => break,
            }
        }
        self.disconnect(&client).await;
        self.clients.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Ship a terminal's output to its owner until the terminal is closed.
async fn sender(term: Arc<Term>) {
    loop {
        term.wake.notified().await;
        let gather = {
            let flow = lock(&term.flow);
            flow.owner.is_some() && flow.pending.len() < 64 * 1024 && !flow.closed && flow.exit.is_none()
        };
        if gather {
            tokio::time::sleep(COALESCE).await;
        }
        if term.flush() {
            break;
        }
    }
}

/// Run the daemon in this (already detached) process until it has been idle long enough.
pub async fn run(home: PathBuf) -> i32 {
    let socket = wire::socket_path(&home);
    if let Some(dir) = socket.parent()
        && let Err(error) = std::fs::create_dir_all(dir)
    {
        tracing::error!("cortexd: {}: {error}", dir.display());
        return 1;
    }
    // The caller holds the lock: a socket file left here belongs to a dead daemon.
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(listener) => listener,
        Err(error) => {
            tracing::error!("cortexd: cannot listen on {}: {error}", socket.display());
            return 1;
        }
    };
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600));
    }
    tracing::info!(pid = std::process::id(), version = wire::DAEMON_VERSION, "cortexd: listening on {}", socket.display());
    let daemon = Arc::new(Daemon {
        terms: Mutex::new(HashMap::new()),
        owner: Mutex::new(None),
        clients: AtomicUsize::new(0),
        next_client: AtomicU64::new(1),
        socket: socket.clone(),
    });
    let mut idle_since: Option<Instant> = None;
    let mut check = tokio::time::interval(Duration::from_secs(15));
    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, _)) => {
                    tokio::spawn(daemon.clone().serve(stream));
                }
                Err(error) => tracing::warn!("cortexd: accept failed: {error}"),
            },
            _ = check.tick() => {
                let idle = daemon.clients.load(Ordering::SeqCst) == 0 && daemon.living() == 0;
                if !idle {
                    idle_since = None;
                } else if idle_since.get_or_insert_with(Instant::now).elapsed() >= IDLE_EXIT {
                    tracing::info!("cortexd: no shells and no client for {IDLE_EXIT:?}; exiting");
                    break;
                }
            }
        }
    }
    let _ = std::fs::remove_file(&socket);
    0
}

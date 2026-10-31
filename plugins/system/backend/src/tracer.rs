//! Traces: record what a process tree does, for a week, so it can be looked at later. Every
//! process scan adds the tree's samples and the processes that came and went; every 2 s its open
//! files and sockets are read (lsof, as monitor mode does) and what changed is added. The records
//! go to the memory plugin (`memory.trace.append`), which keeps them in IronGraph and answers the
//! summaries.
//!
//! Two kinds: a Run (a terminal's command: everything its shell starts while the command runs,
//! with the output at the end) and a recorded process (RECORD, or a member's request). A Run
//! that ended before any scan saw a process of its own leaves no trace: `cd` and a quick `ls` are
//! not worth one.
//!
//! Without sudo this samples, it does not trace system calls: a file opened and closed between
//! two reads, or a process that lived less than a scan, is not seen.
//!
//! A recording (not a Run) survives a restart: while it runs it is a node in the graph,
//! `(:TraceRecording {key: id, pid, root_started, …})-[:ON]->(:Machine)`, retired when it ends;
//! at start those still live are resumed when their process is still the same one.

use crate::graph::{self, Batch, Props, r};
use crate::procs::Snapshot;
use crate::util::now_ms;
use cc_protocol::contracts::memory::{TraceInfo, TraceRecord};
use cc_protocol::contracts::system::OpenFile;
use serde_json::json;
use std::collections::{HashMap, HashSet};

/// The most processes read in one trace (lsof and samples).
const TREE: usize = 64;
/// Records held while the memory plugin cannot take them.
const BACKLOG: usize = 50_000;
/// A trace stops by itself after a week.
const MAX_MS: u64 = 7 * 24 * 60 * 60 * 1000;

#[derive(Debug, Clone)]
struct Live {
    info: TraceInfo,
    /// The traced process; for a Run, its shell (not recorded itself).
    root: u32,
    with_root: bool,
    /// For a Run: the shell's children that started before this (Unix seconds) are not its own.
    since: u64,
    /// The process's start (Unix seconds), so a reused pid is not taken for it after a restart.
    root_started: u64,
    /// pid -> name, of the tree now.
    tree: HashMap<u32, String>,
    /// pid -> what it has open (`fd|kind|name` -> mode).
    open: HashMap<u32, HashMap<String, (OpenFile, String)>>,
    pending: Vec<TraceRecord>,
    /// Written to memory at least once (a Run is only once a process of its own is seen).
    written: bool,
    /// Ended: flushed one last time, then dropped.
    done: bool,
    /// Its asker ends it with [`Tracer::finish`] (which brings its output), not when its
    /// processes are gone.
    held: bool,
    /// When a held trace's processes were first seen gone.
    gone_at: Option<u64>,
}

pub struct Tracer {
    live: HashMap<String, Live>,
    /// Runs that finished before their start was handled (the shell's pid is asked for first).
    finished: Vec<String>,
    /// Recorded traces from before a restart, resumed or closed on the first scan.
    restored: bool,
    /// The recordings the graph holds as live.
    kept: HashSet<String>,
    me: u32,
}

impl Default for Tracer {
    fn default() -> Self {
        // SAFETY: getuid has no preconditions.
        let me = unsafe { libc::getuid() };
        Tracer { live: HashMap::new(), finished: Vec::new(), restored: true, kept: HashSet::new(), me }
    }
}

/// The recordings that were live when the plugin stopped (from the graph).
pub async fn load_recordings() -> Result<Vec<(TraceInfo, u32, bool, u64, u64)>, String> {
    let rows = graph::query_all(
        "MATCH (t:TraceRecording) WHERE t.state IS NULL OR t.state <> 'gone' \
         RETURN t.key, t.label, t.command, t.cwd, t.pid, t.source, t.run_id, t.asked_by, t.started, t.limits, t.root, t.with_root, t.since, t.root_started ORDER BY t.key",
        json!({}),
    )
    .await?;
    Ok(rows
        .iter()
        .map(|row| {
            let info = TraceInfo {
                id: graph::text(&row[0]),
                label: graph::text(&row[1]),
                command: graph::text(&row[2]),
                cwd: graph::text(&row[3]),
                pid: graph::number(&row[4]) as u32,
                source: graph::text(&row[5]),
                run_id: row[6].as_str().map(str::to_owned),
                asked_by: graph::text(&row[7]),
                started: graph::number(&row[8]),
                limits: graph::texts(&row[9]),
                ..Default::default()
            };
            (info, graph::number(&row[10]) as u32, row[11].as_bool().unwrap_or(true), graph::number(&row[12]), graph::number(&row[13]))
        })
        .collect())
}

/// A recording's node, as [`load_recordings`] reads it back.
pub fn recording_batch(info: &TraceInfo, root: u32, with_root: bool, since: u64, root_started: u64) -> Option<Batch> {
    let machine = graph::machine()?;
    let mut batch = Batch::new();
    let unit = batch.unit();
    unit.node("TraceRecording", info.id.clone())
        .p("label", info.label.clone())
        .p("command", info.command.clone())
        .p("cwd", info.cwd.clone())
        .p("pid", info.pid)
        .p("source", info.source.clone())
        .po("run_id", info.run_id.clone())
        .p("asked_by", info.asked_by.clone())
        .p("started", info.started)
        .pl("limits", info.limits.clone())
        .p("root", root)
        .p("with_root", with_root)
        .p("since", since)
        .p("root_started", root_started);
    unit.edge(r("TraceRecording", info.id.clone()), "ON", machine);
    Some(batch)
}

impl Tracer {
    /// Bring back the recordings that were live before a restart; the next scan resumes each
    /// whose process is still the same one, and closes the others.
    pub fn restore(&mut self, list: Vec<(TraceInfo, u32, bool, u64, u64)>) {
        for (info, root, with_root, since, root_started) in list {
            self.kept.insert(info.id.clone());
            self.live.entry(info.id.clone()).or_insert(Live {
                info,
                root,
                with_root,
                since,
                root_started,
                tree: HashMap::new(),
                open: HashMap::new(),
                pending: Vec::new(),
                written: true,
                done: false,
                held: false,
                gone_at: None,
            });
        }
        self.restored = false;
    }

    /// The graph's live recordings brought in line: new ones written, ended ones retired.
    fn save(&mut self) {
        let now: HashSet<String> = self.live.values().filter(|live| !live.done && live.info.source != "run").map(|live| live.info.id.clone()).collect();
        for id in now.difference(&self.kept) {
            let live = &self.live[id];
            if let Some(batch) = recording_batch(&live.info, live.root, live.with_root, live.since, live.root_started) {
                graph::put(batch);
            }
        }
        let gone: Vec<_> = self.kept.difference(&now).map(|id| r("TraceRecording", id.clone())).collect();
        if !gone.is_empty() {
            graph::retire(gone, "ended");
        }
        self.kept = now;
    }

    /// Start recording `pid` and its children.
    pub fn start(&mut self, snapshot: &Snapshot, pid: u32, label: &str, asked_by: &str) -> Result<TraceInfo, String> {
        if let Some(live) = self.live.values().find(|live| live.root == pid && live.with_root && !live.done) {
            return Ok(live.info.clone());
        }
        // Younger than the last scan: it is taken from the next one.
        let fresh = crate::procs::Entry { proc: cc_protocol::contracts::system::Proc { pid, name: format!("pid {pid}"), ..Default::default() }, exe: String::new(), uid: self.me };
        let entry = match snapshot.entries.iter().find(|entry| entry.proc.pid == pid) {
            Some(entry) => entry,
            // SAFETY: kill with signal 0 only checks that the process exists.
            None if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM) => &fresh,
            None => return Err(format!("no process with pid {pid}")),
        };
        let p = &entry.proc;
        let output = if asked_by.is_empty() {
            "Its output is not kept: only commands run in a CortexTerm terminal have their output recorded."
        } else {
            "Its output is not here: it stays with the app that ran it."
        };
        let mut limits = vec![output.to_owned()];
        if entry.uid != self.me {
            limits.push("It belongs to another user: its files and sockets cannot be read without admin.".to_owned());
        }
        let info = TraceInfo {
            id: new_id(pid),
            label: if label.trim().is_empty() { p.name.clone() } else { label.trim().to_owned() },
            command: p.command.clone(),
            pid,
            source: if asked_by.is_empty() { "record".into() } else { "member".into() },
            asked_by: if asked_by.is_empty() { "cortexterm".into() } else { asked_by.to_owned() },
            started: now_ms(),
            limits,
            ..Default::default()
        };
        let live = Live {
            info: info.clone(),
            root: pid,
            with_root: true,
            since: 0,
            root_started: p.started,
            tree: HashMap::new(),
            open: HashMap::new(),
            pending: Vec::new(),
            written: true,
            done: false,
            held: false,
            gone_at: None,
        };
        self.live.insert(info.id.clone(), live);
        self.save();
        Ok(info)
    }

    /// A terminal's command started: trace what its shell starts until it finishes.
    pub fn run_started(&mut self, run_id: &str, command: &str, cwd: &str, started: u64, shell: u32) {
        if self.finished.iter().any(|id| id == run_id) || self.live.values().any(|live| live.info.run_id.as_deref() == Some(run_id)) {
            return;
        }
        let info = TraceInfo {
            id: new_id(shell ^ (started as u32)),
            label: command.chars().take(200).collect(),
            command: command.into(),
            cwd: cwd.into(),
            pid: shell,
            source: "run".into(),
            run_id: Some(run_id.into()),
            asked_by: "cortexterm".into(),
            started,
            ..Default::default()
        };
        let live = Live {
            info: info.clone(),
            root: shell,
            with_root: false,
            since: (started / 1000).saturating_sub(1),
            root_started: 0,
            tree: HashMap::new(),
            open: HashMap::new(),
            pending: Vec::new(),
            written: false,
            done: false,
            held: false,
            gone_at: None,
        };
        self.live.insert(info.id, live);
    }

    /// A held trace ([`Tracer::hold`]) ended: its output lines (`(at, text)`) and exit code.
    pub fn finish(&mut self, id: &str, ended: u64, exit_code: Option<i32>, output: Vec<(u64, String)>) {
        let Some(live) = self.live.get_mut(id) else { return };
        live.pending.extend(output.into_iter().map(|(at, text)| TraceRecord { at, kind: "output".into(), text, ..Default::default() }));
        live.pending.push(TraceRecord { at: ended, kind: "exit".into(), code: exit_code, ..Default::default() });
        live.info.exit_code = exit_code;
        if !live.done {
            end(live, ended);
        }
    }

    /// A terminal's command finished: its trace ends with the exit code and the output lines
    /// (`(at, text)`). None when it left no trace.
    pub fn run_finished(&mut self, run_id: &str, ended: u64, exit_code: Option<i32>, output: Vec<(u64, String)>) -> Option<String> {
        let Some(id) = self.live.iter().find(|(_, live)| live.info.run_id.as_deref() == Some(run_id) && !live.done).map(|(id, _)| id.clone()) else {
            self.finished.push(run_id.to_owned());
            if self.finished.len() > 200 {
                self.finished.remove(0);
            }
            return None;
        };
        let live = self.live.get_mut(&id)?;
        if !live.written {
            self.live.remove(&id);
            return None;
        }
        live.pending.extend(output.into_iter().map(|(at, text)| TraceRecord { at, kind: "output".into(), text, ..Default::default() }));
        live.pending.push(TraceRecord { at: ended, kind: "exit".into(), code: exit_code, ..Default::default() });
        live.info.exit_code = exit_code;
        end(live, ended);
        Some(id)
    }

    /// A finished Run's output lines, added before its last records go out.
    pub fn add_output(&mut self, id: &str, lines: Vec<(u64, String)>) {
        if let Some(live) = self.live.get_mut(id) {
            let exit = live.pending.iter().position(|record| record.kind == "exit").unwrap_or(live.pending.len());
            let output = lines.into_iter().map(|(at, text)| TraceRecord { at, kind: "output".into(), text, ..Default::default() });
            live.pending.splice(exit..exit, output);
        }
    }

    pub fn stop(&mut self, id: &str) -> Option<TraceInfo> {
        let live = self.live.get_mut(id)?;
        if !live.done {
            end(live, now_ms());
        }
        let info = live.info.clone();
        self.save();
        Some(info)
    }

    /// A trace started with [`Tracer::start`] that its asker ends ([`Tracer::finish`]).
    pub fn hold(&mut self, id: &str) {
        if let Some(live) = self.live.get_mut(id) {
            live.held = true;
            live.info.limits.retain(|limit| !limit.starts_with("Its output"));
        }
    }

    pub fn is_live(&self, id: &str) -> bool {
        self.live.get(id).is_some_and(|live| !live.done)
    }

    /// One process scan: each tree's processes that came and went, and a sample of each.
    pub fn scan(&mut self, snapshot: &Snapshot) {
        let at = snapshot.at;
        let by_pid: HashMap<u32, &crate::procs::Entry> = snapshot.entries.iter().map(|entry| (entry.proc.pid, entry)).collect();
        let mut kids: HashMap<u32, Vec<u32>> = HashMap::new();
        for entry in &snapshot.entries {
            kids.entry(entry.proc.ppid).or_default().push(entry.proc.pid);
        }
        if !self.restored {
            self.restored = true;
            for live in self.live.values_mut() {
                let same = by_pid.get(&live.root).is_some_and(|entry| live.root_started == 0 || entry.proc.started == live.root_started);
                if !same {
                    live.info.limits.push("Recording stopped when CortexTerm restarted.".into());
                    end(live, at);
                }
            }
        }
        for live in self.live.values_mut().filter(|live| !live.done) {
            // A scan taken before the trace began may not have its process yet.
            let gone = !by_pid.contains_key(&live.root) && at > live.info.started;
            // A held trace whose asker never ends it (it stopped) ends a minute after its processes.
            if gone && live.held && at.saturating_sub(*live.gone_at.get_or_insert(at)) > 60_000 {
                live.info.limits.push("The app that ran it did not say how it ended.".into());
                end(live, at);
                continue;
            }
            if gone && live.held {
                for (pid, name) in live.tree.drain() {
                    live.pending.push(TraceRecord { at, kind: "end".into(), pid, name, ..Default::default() });
                }
                live.open.clear();
                continue;
            }
            if gone || at.saturating_sub(live.info.started) > MAX_MS {
                end(live, at);
                continue;
            }
            // The tree: the root (when recorded), then its descendants breadth first.
            let mut tree: Vec<u32> = Vec::new();
            let mut queue: Vec<u32> = vec![live.root];
            let mut at_queue = 0;
            while at_queue < queue.len() && tree.len() < TREE {
                let pid = queue[at_queue];
                at_queue += 1;
                if pid != live.root || live.with_root {
                    tree.push(pid);
                }
                for &child in kids.get(&pid).map(Vec::as_slice).unwrap_or(&[]) {
                    // A Run's own processes are the shell's children started since it began.
                    let own = pid != live.root || live.with_root || by_pid.get(&child).is_some_and(|entry| entry.proc.started >= live.since);
                    if own && child != live.root {
                        queue.push(child);
                    }
                }
            }
            let now: HashSet<u32> = tree.iter().copied().collect();
            for (pid, name) in live.tree.iter().filter(|(pid, _)| !now.contains(pid)) {
                live.pending.push(TraceRecord { at, kind: "end".into(), pid: *pid, name: name.clone(), ..Default::default() });
            }
            live.tree.retain(|pid, _| now.contains(pid));
            live.open.retain(|pid, _| now.contains(pid));
            for pid in tree {
                let Some(entry) = by_pid.get(&pid) else { continue };
                let p = &entry.proc;
                if let std::collections::hash_map::Entry::Vacant(slot) = live.tree.entry(pid) {
                    slot.insert(p.name.clone());
                    live.pending.push(TraceRecord { at, kind: "start".into(), pid, ppid: p.ppid, name: p.name.clone(), text: p.command.clone(), ..Default::default() });
                }
                live.pending.push(TraceRecord {
                    at,
                    kind: "sample".into(),
                    pid,
                    cpu: Some(p.cpu),
                    memory: Some(p.memory),
                    gpu: p.gpu,
                    disk_write: Some(p.disk_write),
                    ..Default::default()
                });
            }
            if !live.tree.is_empty() {
                live.written = true;
            }
        }
    }

    /// The processes of the terminal commands running now, each with its command.
    pub fn run_pids(&self) -> Vec<(u32, String)> {
        self.live
            .values()
            .filter(|live| live.info.source == "run" && !live.done)
            .flat_map(|live| live.tree.keys().map(move |pid| (*pid, live.info.command.clone())))
            .collect()
    }

    /// The processes whose files to read now.
    pub fn file_pids(&self) -> Vec<u32> {
        self.live.values().filter(|live| !live.done && live.written).flat_map(|live| live.tree.keys().copied()).collect()
    }

    /// One read of open files and sockets: what each traced process opened, closed, connected
    /// to and listens on since the last read.
    pub fn files(&mut self, read: &HashMap<u32, Vec<OpenFile>>) {
        let at = now_ms();
        for live in self.live.values_mut().filter(|live| !live.done && live.written) {
            for &pid in live.tree.keys() {
                let Some(files) = read.get(&pid) else { continue };
                let mut now: HashMap<String, (OpenFile, String)> = HashMap::new();
                for file in files {
                    // The program's own mappings and the root folder say nothing new.
                    if !(file.fd.chars().all(|c| c.is_ascii_digit()) || file.fd == "cwd") {
                        continue;
                    }
                    let key = format!("{}|{}|{}", file.fd, file.kind, file.name);
                    now.insert(key, (file.clone(), file.mode.clone()));
                }
                let before = live.open.remove(&pid).unwrap_or_default();
                for (key, (file, mode)) in &now {
                    if before.contains_key(key) {
                        continue;
                    }
                    if let Some(record) = opened(at, pid, file, mode) {
                        live.pending.push(record);
                    }
                }
                for (key, (file, _)) in &before {
                    if !now.contains_key(key) && file.kind == "file" {
                        live.pending.push(TraceRecord { at, kind: "close".into(), pid, text: file.name.clone(), ..Default::default() });
                    }
                }
                live.open.insert(pid, now);
            }
        }
    }

    /// What to send now: each trace with records (or that ended), its records taken. Ended
    /// traces are dropped once taken.
    pub fn take(&mut self) -> Vec<(TraceInfo, Vec<TraceRecord>)> {
        let mut out = Vec::new();
        let mut ended = Vec::new();
        for (id, live) in self.live.iter_mut() {
            if !live.written {
                if live.done {
                    ended.push(id.clone());
                }
                continue;
            }
            if !live.pending.is_empty() || live.done {
                out.push((live.info.clone(), std::mem::take(&mut live.pending)));
            }
            if live.done {
                ended.push(id.clone());
            }
        }
        if !ended.is_empty() {
            for id in ended {
                self.live.remove(&id);
            }
            self.save();
        }
        out
    }

    /// Records the memory plugin did not take go back, the oldest dropped past the backlog.
    pub fn put_back(&mut self, info: TraceInfo, mut records: Vec<TraceRecord>) {
        let live = self.live.entry(info.id.clone()).or_insert_with(|| Live {
            info: info.clone(),
            root: info.pid,
            with_root: true,
            since: 0,
            root_started: 0,
            tree: HashMap::new(),
            open: HashMap::new(),
            pending: Vec::new(),
            written: true,
            done: true,
            held: false,
            gone_at: None,
        });
        records.append(&mut live.pending);
        if records.len() > BACKLOG {
            records.drain(..records.len() - BACKLOG);
        }
        live.pending = records;
    }
}

fn end(live: &mut Live, at: u64) {
    live.info.ended = Some(at);
    for (pid, name) in live.tree.drain() {
        live.pending.push(TraceRecord { at, kind: "end".into(), pid, name, ..Default::default() });
    }
    live.open.clear();
    live.done = true;
}

/// A newly seen open file or socket as a record: `open` for a file, `connect` for a connection,
/// `listen` for a listening socket; None for pipes and the like.
fn opened(at: u64, pid: u32, file: &OpenFile, mode: &str) -> Option<TraceRecord> {
    let (kind, text) = match file.kind.as_str() {
        "file" => ("open", file.name.clone()),
        "tcp" | "udp" if file.state == "LISTEN" => ("listen", file.name.clone()),
        "tcp" | "udp" => ("connect", file.name.split_once("->").map(|(_, remote)| remote.to_owned())?),
        _ => return None,
    };
    Some(TraceRecord { at, kind: kind.into(), pid, text, mode: mode.into(), ..Default::default() })
}

/// `t-` and 12 hex digits from the time and a number.
fn new_id(salt: u32) -> String {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0) as u64;
    let mixed = nanos ^ (u64::from(salt)).rotate_left(29) ^ nanos.rotate_right(17);
    format!("t-{:012x}", mixed & 0xffff_ffff_ffff)
}

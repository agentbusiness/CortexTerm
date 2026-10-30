//! Processes: the background scan's snapshot, listed flat, by app or as a tree; one process in
//! detail; signals for the user's own processes.

use crate::host;
use cc_protocol::RpcError;
use cc_protocol::contracts::system::{MonitorReport, Proc, ProcSample, ProcessDetail, ProcessGroup, ProcessList, ProcessesParams, SignalParams};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::path::Path;

/// One process of the snapshot.
#[derive(Debug, Clone, Default)]
pub struct Entry {
    pub proc: Proc,
    pub exe: String,
    pub uid: u32,
}

#[derive(Debug, Clone, Default)]
pub struct Snapshot {
    pub at: u64,
    pub entries: Vec<Entry>,
}

/// The app a process belongs to: the outermost `.app` bundle in its executable path, "System" for
/// the kernel and system daemons, else its own name.
pub fn app_of(exe: &str, name: &str, pid: u32, uid: u32) -> String {
    if let Some(end) = exe.find(".app/") {
        return exe[..end].rsplit('/').next().unwrap_or(name).to_owned();
    }
    let system = ["/System/", "/usr/libexec/", "/usr/sbin/", "/sbin/"];
    if pid == 0 || system.iter().any(|prefix| exe.starts_with(prefix)) || (exe.is_empty() && uid == 0) {
        return "System".to_owned();
    }
    name.to_owned()
}

fn matches(entry: &Entry, filter: &str) -> bool {
    if filter.is_empty() {
        return true;
    }
    if let Some(port) = filter.strip_prefix(':') {
        return port.parse::<u16>().map(|port| entry.proc.ports.contains(&port)).unwrap_or(false);
    }
    entry.proc.name.to_lowercase().contains(filter)
        || entry.proc.command.to_lowercase().contains(filter)
        || entry.proc.app.to_lowercase().contains(filter)
        || entry.proc.pid.to_string() == filter
}

/// What a row is sorted on: name, cpu, memory, gpu.
type Key<'a> = (&'a str, f32, u64, f32);

fn compare(sort: &str, a: Key, b: Key) -> Ordering {
    match sort {
        "memory" => b.2.cmp(&a.2),
        "gpu" => b.3.partial_cmp(&a.3).unwrap_or(Ordering::Equal).then(b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal)),
        "name" => a.0.to_lowercase().cmp(&b.0.to_lowercase()),
        _ => b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal),
    }
}

fn by(sort: &str, a: &Proc, b: &Proc) -> Ordering {
    compare(sort, key_of(a), key_of(b)).then(a.pid.cmp(&b.pid))
}

fn key_of(p: &Proc) -> Key<'_> {
    (&p.name, p.cpu, p.memory, p.gpu.unwrap_or(0.0))
}

fn group_key(g: &ProcessGroup) -> Key<'_> {
    (&g.name, g.cpu, g.memory, g.gpu.unwrap_or(0.0))
}

/// The sum of the known GPU shares; `None` when none is known.
fn gpu_sum<'a>(procs: impl IntoIterator<Item = &'a Proc>) -> Option<f32> {
    procs.into_iter().filter_map(|p| p.gpu).reduce(|a, b| a + b).map(|sum| sum.min(100.0))
}

pub fn list(snapshot: &Snapshot, params: &ProcessesParams) -> ProcessList {
    let filter = params.filter.trim().to_lowercase();
    let limit = if params.limit == 0 { 200 } else { params.limit as usize };
    let sort = params.sort.as_str();
    let mut procs: Vec<Proc> = snapshot.entries.iter().filter(|entry| matches(entry, &filter)).map(|entry| entry.proc.clone()).collect();
    let total = procs.len() as u32;
    let groups = match params.group.as_str() {
        "app" => {
            let mut groups: HashMap<String, ProcessGroup> = HashMap::new();
            for proc in procs {
                let group = groups.entry(proc.app.clone()).or_insert_with(|| ProcessGroup { name: proc.app.clone(), ..Default::default() });
                group.cpu += proc.cpu;
                group.memory += proc.memory;
                group.disk_write += proc.disk_write;
                group.ports.extend(&proc.ports);
                group.processes.push(proc);
            }
            let mut groups: Vec<ProcessGroup> = groups.into_values().collect();
            for group in &mut groups {
                group.gpu = gpu_sum(&group.processes);
                group.ports.sort_unstable();
                group.ports.dedup();
                group.processes.sort_by(|a, b| by(sort, a, b));
            }
            groups.sort_by(|a, b| compare(sort, group_key(a), group_key(b)).then(a.name.cmp(&b.name)));
            groups.truncate(limit);
            groups
        }
        "tree" => {
            let pids: HashSet<u32> = procs.iter().map(|p| p.pid).collect();
            let mut children: HashMap<u32, Vec<Proc>> = HashMap::new();
            let mut roots = Vec::new();
            for proc in procs {
                if proc.ppid == proc.pid || !pids.contains(&proc.ppid) {
                    roots.push(proc);
                } else {
                    children.entry(proc.ppid).or_default().push(proc);
                }
            }
            roots.sort_by(|a, b| by(sort, a, b));
            for list in children.values_mut() {
                list.sort_by(|a, b| by(sort, a, b));
            }
            let mut ordered = Vec::new();
            let mut stack: Vec<Proc> = roots.into_iter().rev().collect();
            while let Some(proc) = stack.pop() {
                if let Some(kids) = children.remove(&proc.pid) {
                    stack.extend(kids.into_iter().rev());
                }
                ordered.push(proc);
                if ordered.len() >= limit {
                    break;
                }
            }
            vec![summed(ordered)]
        }
        _ => {
            procs.sort_by(|a, b| by(sort, a, b));
            procs.truncate(limit);
            vec![summed(procs)]
        }
    };
    ProcessList { at: snapshot.at, groups, total }
}

/// One unnamed group holding every listed process (flat and tree views).
fn summed(processes: Vec<Proc>) -> ProcessGroup {
    let mut ports: Vec<u16> = processes.iter().flat_map(|p| p.ports.iter().copied()).collect();
    ports.sort_unstable();
    ports.dedup();
    ProcessGroup {
        name: String::new(),
        cpu: processes.iter().map(|p| p.cpu).sum(),
        memory: processes.iter().map(|p| p.memory).sum(),
        gpu: gpu_sum(&processes),
        disk_write: processes.iter().map(|p| p.disk_write).sum(),
        ports,
        processes,
    }
}

/// One process in detail (blocking: runs `codesign` the first time it sees an executable, and
/// `lsof` for its open files).
pub fn detail(snapshot: &Snapshot, pid: u32, history: Vec<ProcSample>, monitor: Option<MonitorReport>) -> Result<ProcessDetail, RpcError> {
    let by_pid: HashMap<u32, &Entry> = snapshot.entries.iter().map(|e| (e.proc.pid, e)).collect();
    let entry = by_pid.get(&pid).ok_or_else(|| RpcError::not_found(format!("no process with pid {pid}")))?;
    let mut parents = Vec::new();
    let mut seen = HashSet::from([pid]);
    let mut next = entry.proc.ppid;
    while let Some(parent) = by_pid.get(&next) {
        if !seen.insert(next) {
            break;
        }
        parents.push((next, parent.proc.name.clone()));
        if next <= 1 {
            break;
        }
        next = parent.proc.ppid;
    }
    if parents.is_empty() && entry.proc.ppid == 1 {
        parents.push((1, "launchd".into()));
    }
    let (cwd, open_files, threads) = host::process_facts(pid);
    let exe = Path::new(&entry.exe);
    let (signature, team_id) = if entry.exe.is_empty() { ("unknown".to_owned(), String::new()) } else { host::signature(exe) };
    let quarantined = !entry.exe.is_empty() && host::quarantined(exe);
    let launchd_managed = cfg!(target_os = "macos") && entry.proc.ppid == 1 && (entry.uid == 0 || host::launchd_job_pids().contains(&pid));
    let lifetime = host::lifetime(pid);
    let thread_list = host::threads(pid);
    let files = host::open_files(&[pid]).remove(&pid).unwrap_or_default();
    let state = if lifetime.zombie {
        "zombie"
    } else if lifetime.stopped {
        "stopped"
    } else if thread_list.iter().any(|t| t.state == "running") || entry.proc.cpu >= 1.0 {
        "running"
    } else if thread_list.is_empty() {
        ""
    } else {
        "sleeping"
    };
    let mut children: Vec<Proc> = snapshot.entries.iter().filter(|e| e.proc.ppid == pid && e.proc.pid != pid).map(|e| e.proc.clone()).collect();
    children.sort_by(|a, b| by("cpu", a, b));
    Ok(ProcessDetail {
        process: entry.proc.clone(),
        executable: entry.exe.clone(),
        cwd,
        open_files,
        threads,
        parents,
        signature,
        team_id,
        quarantined,
        launchd_managed,
        state: state.into(),
        cpu_time_ms: lifetime.cpu_time_ms,
        disk_read_total: lifetime.disk_read,
        disk_written_total: lifetime.disk_written,
        peak_memory: lifetime.peak_memory,
        history,
        thread_list,
        files,
        children,
        monitor,
    })
}

/// Send a signal to one of this user's processes.
pub fn signal(snapshot: &Snapshot, params: &SignalParams) -> Result<Value, RpcError> {
    let signal = match params.signal.trim().trim_start_matches("SIG").to_uppercase().as_str() {
        "TERM" => libc::SIGTERM,
        "KILL" => libc::SIGKILL,
        "INT" => libc::SIGINT,
        "HUP" => libc::SIGHUP,
        "STOP" => libc::SIGSTOP,
        "CONT" => libc::SIGCONT,
        other => return Err(RpcError::invalid_params(format!("unknown signal {other:?}; use TERM, KILL, INT, HUP, STOP or CONT"))),
    };
    let pid = params.pid;
    if pid <= 1 || pid == std::process::id() {
        return Err(RpcError::invalid_params(format!("pid {pid} cannot be signalled from here")));
    }
    let entry =
        snapshot.entries.iter().find(|e| e.proc.pid == pid).ok_or_else(|| RpcError::not_found(format!("no process with pid {pid}")))?;
    // SAFETY: getuid has no preconditions.
    let me = unsafe { libc::getuid() };
    let denied = || RpcError::new("denied", format!("{} (pid {pid}) belongs to another user; signalling it needs admin", entry.proc.name));
    if entry.uid != me {
        return Err(denied());
    }
    // SAFETY: plain kill(2) on a pid we checked belongs to this user.
    if unsafe { libc::kill(pid as i32, signal) } != 0 {
        let error = std::io::Error::last_os_error();
        return match error.raw_os_error() {
            Some(libc::EPERM) => Err(denied()),
            Some(libc::ESRCH) => Err(RpcError::not_found(format!("pid {pid} has already exited"))),
            _ => Err(RpcError::internal(format!("kill {pid}: {error}"))),
        };
    }
    let name = params.signal.trim().trim_start_matches("SIG").to_uppercase();
    Ok(json!({"ok": true, "detail": format!("Sent {name} to {} (pid {pid}).", entry.proc.name)}))
}

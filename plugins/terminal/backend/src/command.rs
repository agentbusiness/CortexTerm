//! The command service (`terminal.command`, shared through the mesh with the other apps on this
//! machine): a command another app asks for, run in the person's login shell (`$SHELL -lc`, so
//! their PATH, toolchains and profile), in the folder it names. It is a Run like a typed command
//! (shown in CortexTerm, its output kept), its output streams back to the caller, and the answer is
//! a job the caller can read again or stop.
//!
//! - `sandboxed`: it runs in the write sandbox both apps share (`sandbox-kit`, the one CortexCode's
//!   own commands run in): writes only in its folder, the temp and package-cache folders, and the
//!   folders the caller names in `writable`.
//! - `monitor`: the system plugin traces it (`system.trace.run`); the answer names the trace and
//!   its one line.
//! - The risk engine ([`crate::assess`]) decides, not the caller: a command that deletes or needs
//!   admin, or that writes or talks to the network outside the sandbox, does not run until the
//!   person approved it in the asking app's window (`approved`).
//! - Each asking session has a Shell of its own here, `service.<app>.<session>`. The job is the
//!   Run's `(:CommandRun)` node, with `job_state`, `job_text`, `tail`, `trace`, `trace_line`,
//!   `caller_*`, `purpose` and `pgid` on it, so `jobs.get` answers for as long as the Run is kept
//!   (its output 30 days, its trace 7). A job left running when this plugin stopped is `lost` at
//!   the next start (its processes killed; it never runs again).
//! - Events for the caller (the mesh sends them to the app in `node` only):
//!   `terminal.command.ended` for every job, `terminal.command.matched` for a background job's
//!   `watch` (a matching line, at most one per 5 s; a silent stretch, once).

use crate::{assess, threat};
use crate::marks::ShellEnv;
use crate::store::{self, Store};
use cc_protocol::contracts::service::{self as svc, Audience, Caller, CommandEnded, CommandMatched, Job, NeedsApproval, Share, ShareList, SharedMethod};
use cc_protocol::contracts::terminal::{CommandRunParams, Run, RunOutputParams, topics};
use cc_protocol::{Ctx, ItemSink, RpcError, codes};
use cc_sandbox_kit::sandbox::Policy;
use serde_json::{Map, Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

/// A command gets this long unless it asks for another limit.
const TIMEOUT: Duration = Duration::from_secs(600);
/// A background one at most this long.
const BACKGROUND: Duration = Duration::from_secs(24 * 3600);
/// Finished jobs remembered for `jobs.list` / `jobs.get`.
const KEEP: usize = 50;
const TAIL: usize = 40;
/// Output lines handed to the trace of a monitored command.
const TRACE_LINES: usize = 20_000;
/// A trace is kept this long, a Run's output this long.
const TRACE_DAYS: u64 = 7;
const OUTPUT_DAYS: u64 = 30;
const DAY_MS: u64 = 24 * 3600 * 1000;

type Emit = Arc<dyn Fn(&str, Value) + Send + Sync>;

struct Entry {
    job: Job,
    pgid: Option<i32>,
}

pub struct Commands {
    store: Option<Arc<Store>>,
    emit: Emit,
    home: PathBuf,
    jobs: Mutex<VecDeque<Entry>>,
    policy: OnceLock<Policy>,
    login_path: OnceLock<Option<String>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn now_ms() -> u64 {
    cc_protocol::contracts::now_ms()
}

fn shell() -> PathBuf {
    PathBuf::from(crate::login_shell())
}

impl Commands {
    pub fn new(store: Option<Arc<Store>>, emit: Emit, home: PathBuf) -> Arc<Self> {
        Arc::new(Commands { store, emit, home, jobs: Mutex::new(VecDeque::new()), policy: OnceLock::new(), login_path: OnceLock::new() })
    }

    /// The person's PATH as their login shell sets it (read once), for the risk engine to find
    /// programs where the command will.
    fn login_path(&self) -> Option<String> {
        self.login_path
            .get_or_init(|| {
                let output = std::process::Command::new(shell()).args(["-lc", "printf %s \"$PATH\""]).stdin(Stdio::null()).output().ok()?;
                let path = String::from_utf8_lossy(&output.stdout).trim().to_owned();
                (!path.is_empty()).then_some(path)
            })
            .clone()
    }

    fn policy(&self) -> &Policy {
        self.policy.get_or_init(|| {
            let data = store::default_dir().unwrap_or_else(|| self.home.join("plugins-data").join("terminal"));
            Policy::new(&self.home, &data, &[])
        })
    }

    fn remember(&self, job: Job, pgid: Option<i32>) {
        let mut jobs = lock(&self.jobs);
        jobs.retain(|entry| entry.job.id != job.id);
        jobs.push_back(Entry { job, pgid });
        while jobs.len() > KEEP && jobs.front().is_some_and(|entry| entry.job.ended.is_some()) {
            jobs.pop_front();
        }
    }

    fn update(&self, id: &str, change: impl FnOnce(&mut Job)) {
        if let Some(entry) = lock(&self.jobs).iter_mut().find(|entry| entry.job.id == id) {
            change(&mut entry.job);
        }
    }

    pub fn job(&self, id: &str) -> Result<Job, RpcError> {
        lock(&self.jobs).iter().find(|entry| entry.job.id == id).map(|entry| entry.job.clone()).ok_or_else(|| RpcError::not_found(format!("no command job {id}")))
    }

    /// `jobs.get {id, size?, at?}`: the job (from memory, else from its Run in the graph) and, when
    /// it was traced and a size or a moment is asked, its trace in that size as `detail`.
    pub async fn get(&self, ctx: &Ctx, params: Value) -> Result<Job, RpcError> {
        let id = params.get("id").and_then(Value::as_str).ok_or_else(|| RpcError::invalid_params("`id` is needed"))?.to_owned();
        let size = params.get("size").and_then(Value::as_str).unwrap_or("").to_owned();
        let at = params.get("at").and_then(Value::as_u64);
        let mut job = match self.job(&id) {
            Ok(job) => job,
            Err(error) => self.stored(&id).await?.ok_or(error)?,
        };
        if let Some(trace) = job.trace.as_deref().and_then(|t| t.strip_prefix("trace://")).map(str::to_owned)
            && (!size.is_empty() || at.is_some())
        {
            let mut ask = json!({"id": trace});
            match at {
                Some(at) => ask["at"] = json!(at),
                None => ask["size"] = json!(size),
            }
            job.detail = ctx.call("system.trace.read", ask).await.ok();
        }
        Ok(job)
    }

    /// A job from its Run node (one this process no longer holds).
    async fn stored(&self, id: &str) -> Result<Option<Job>, RpcError> {
        let Some(store) = &self.store else { return Ok(None) };
        if !store::valid_id(id) {
            return Ok(None);
        }
        let rows = store
            .query(
                "MATCH (r:CommandRun {key: $id}) RETURN r.started_ms, r.finished_ms, r.exit_code, r.duration_ms, r.job_state, r.job_text, r.tail, r.trace, r.trace_line LIMIT 1",
                json!({"id": id}),
            )
            .await?;
        let Some(row) = rows.first() else { return Ok(None) };
        let text = |i: usize| row.get(i).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned);
        let ended = row.get(1).and_then(Value::as_u64);
        let exit_code = row.get(2).and_then(Value::as_i64).map(|code| code as i32);
        let state = text(4).unwrap_or_else(|| match (ended, exit_code) {
            (None, _) => "running".into(),
            (Some(_), Some(0)) => "done".into(),
            _ => "failed".into(),
        });
        let mut job = Job {
            id: id.to_owned(),
            state,
            started: row.first().and_then(Value::as_u64).unwrap_or(0),
            ended,
            exit_code,
            duration_ms: row.get(3).and_then(Value::as_u64).unwrap_or(0),
            tail: row.get(6).and_then(Value::as_array).map(|lines| lines.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default(),
            trace: text(7),
            trace_line: text(8),
            ..Job::default()
        };
        job.text = text(5).unwrap_or_else(|| job_text(&job));
        // What is no longer kept, so the reader does not ask for it.
        let age = ended.map_or(0, |ended| now_ms().saturating_sub(ended));
        let mut gone = Vec::new();
        if job.trace.is_some() && age > TRACE_DAYS * DAY_MS {
            gone.push("its metrics (traces are kept 7 days)");
        }
        if age > OUTPUT_DAYS * DAY_MS {
            gone.push("its output (kept 30 days)");
        }
        if !gone.is_empty() {
            job.text.push_str(&format!("\nno longer kept: {}", gone.join(", ")));
        }
        Ok(Some(job))
    }

    /// Write the job's own properties on its Run node, through the store's outbox after the Run
    /// itself (they are not the Run's: a later write of the Run leaves them).
    fn record(&self, id: &str, props: Map<String, Value>) {
        if let Some(store) = &self.store {
            store.job(id, props);
        }
    }

    /// At start: the jobs a stopped instance left running are lost. Their processes are killed
    /// (the group, when it is still the one the job started), the caller hears `ended`, and
    /// nothing runs again.
    pub async fn recover(self: Arc<Self>) {
        let Some(store) = self.store.clone() else { return };
        let mut rows = None;
        for _ in 0..60 {
            match store
                .query(
                    "MATCH (r:CommandRun)-[:IN_SHELL]->(s:Shell) WHERE s.key STARTS WITH 'service' AND r.finished_ms IS NULL \
                     RETURN r.key, r.started_ms, r.pgid, r.caller_node, r.caller_session",
                    json!({}),
                )
                .await
            {
                Ok(found) => {
                    rows = Some(found);
                    break;
                }
                Err(_) => tokio::time::sleep(Duration::from_secs(5)).await,
            }
        }
        for row in rows.unwrap_or_default() {
            let Some(id) = row.first().and_then(Value::as_str).map(str::to_owned) else { continue };
            if lock(&self.jobs).iter().any(|entry| entry.job.id == id) {
                continue;
            }
            let started = row.get(1).and_then(Value::as_u64).unwrap_or(0);
            if let Some(pgid) = row.get(2).and_then(Value::as_i64).map(|pgid| pgid as i32) {
                kill_if_ours(pgid, started);
            }
            let ended = now_ms();
            let mut job = Job { id: id.clone(), state: "lost".into(), started, ended: Some(ended), duration_ms: ended.saturating_sub(started), ..Job::default() };
            job.text = job_text(&job);
            let mut props = Map::new();
            props.insert("finished_ms".into(), json!(ended));
            props.insert("duration_ms".into(), json!(job.duration_ms));
            props.insert("job_state".into(), json!("lost"));
            props.insert("job_text".into(), json!(job.text));
            self.record(&id, props);
            let text = |i: usize| row.get(i).and_then(Value::as_str).unwrap_or("").to_owned();
            let ended = CommandEnded { id, node: text(3), session_id: text(4), job };
            (self.emit)(svc::topics::COMMAND_ENDED, serde_json::to_value(&ended).unwrap_or(Value::Null));
        }
    }

    pub fn jobs(&self) -> Value {
        let jobs: Vec<Job> = lock(&self.jobs).iter().rev().map(|entry| entry.job.clone()).collect();
        json!({"jobs": jobs})
    }

    /// Stop a running job: its whole process group, TERM then KILL.
    pub fn stop(&self, id: &str) -> Result<Job, RpcError> {
        let pgid = lock(&self.jobs).iter().find(|entry| entry.job.id == id).and_then(|entry| entry.pgid);
        if let Some(pgid) = pgid {
            // SAFETY: the job runs in its own process group, created for it at spawn.
            unsafe { libc::killpg(pgid, libc::SIGTERM) };
            std::thread::spawn(move || {
                std::thread::sleep(Duration::from_secs(3));
                // SAFETY: as above; a group that is gone makes this a no-op.
                unsafe { libc::killpg(pgid, libc::SIGKILL) };
            });
            self.update(id, |job| job.state = "stopped".into());
        }
        self.job(id)
    }

    pub async fn output(&self, params: RunOutputParams) -> Result<Value, RpcError> {
        let store = self.store.as_ref().ok_or_else(|| RpcError::new(codes::UNAVAILABLE, "Runs are not recorded here"))?;
        cc_protocol::to_value(&store.output(&params).await?)
    }

    /// Run one command for a caller (see the module comment).
    pub async fn run(self: &Arc<Self>, ctx: Ctx, params: Value, items: ItemSink, cancel: CancellationToken) -> Result<Value, RpcError> {
        let p: CommandRunParams = cc_protocol::parse_params(params)?;
        if p.command.trim().is_empty() {
            return Err(RpcError::invalid_params("no command"));
        }
        let cwd = expand(&p.cwd, &self.home);
        if !cwd.is_absolute() || !cwd.is_dir() {
            return Err(RpcError::invalid_params(format!("`{}` is not a folder on this machine", p.cwd)));
        }
        let program = match p.shell.as_str() {
            "" => shell(),
            "bash" => PathBuf::from("/bin/bash"),
            other => return Err(RpcError::invalid_params(format!("shell `{other}`: only `bash`, or none for the person's own"))),
        };
        let watch = match &p.options.watch {
            Some(_) if !p.options.background => return Err(RpcError::invalid_params("`watch` is for a background run")),
            Some(watch) => Some(Watcher::new(watch)?),
            None => None,
        };
        let caller = p.caller.clone().unwrap_or_default();
        let asked_by = Some(caller.app.clone()).filter(|app| !app.is_empty()).unwrap_or_else(|| "service".into());
        let term_id = shell_id(&caller);
        let id = format!("run-{}", uuid::Uuid::new_v4().simple());
        let started = now_ms();
        let mut job = Job { id: id.clone(), state: "running".into(), started, ..Job::default() };
        let path: Vec<PathBuf> = p.path.iter().map(|dir| expand(dir, &self.home)).filter(|dir| dir.is_absolute()).collect();

        // The risk engine decides whether it may run without the person.
        let search = std::iter::once(path.iter().map(|dir| dir.to_string_lossy().into_owned()).collect::<Vec<_>>().join(":"))
            .chain(self.login_path())
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>()
            .join(":");
        let env = ShellEnv { path: Some(search).filter(|s| !s.is_empty()), aliases: HashMap::new(), functions: Default::default() };
        let (command, check_cwd) = (p.command.clone(), cwd.clone());
        let assessment = tokio::task::spawn_blocking(move || assess::assess(&command, &assess::Shell { env: &env, cwd: &check_cwd }, false))
            .await
            .map_err(|e| RpcError::internal(format!("assess task failed: {e}")))?;
        // A high finding of the paste guard needs the person, in the sandbox too.
        let high: Vec<&str> = assessment.threats.iter().filter(|t| t.severity == "high").map(|t| t.text.as_str()).collect();
        let grave = matches!(assessment.risk.as_str(), "delete" | "admin") || !high.is_empty();
        let outside = !p.options.sandboxed && assessment.risk != "read";
        if (grave || outside) && !p.options.approved {
            let why = if !high.is_empty() {
                high.join(" ")
            } else if assessment.reasons.is_empty() {
                assessment.risk.clone()
            } else {
                assessment.reasons.join(", ")
            };
            let reason = if grave { why } else { format!("{why}, outside the sandbox") };
            return cc_protocol::to_value(&refused(job, &assessment.risk, reason));
        }

        // The process: the shell, in the sandbox when asked; the caller's folders first in PATH.
        let mut command = if p.options.sandboxed {
            let policy = match caller_home(&caller) {
                Some(home) => self.policy().for_caller(&home),
                None => self.policy().clone(),
            };
            let writable: Vec<PathBuf> = p.options.writable.iter().map(|path| expand(path, &self.home)).filter(|path| path.is_absolute()).collect();
            let sandbox = match policy.unavailable() {
                Some(why) => Err(format!("the sandbox cannot run here: {why}")),
                None => policy.sandbox(&cwd, None, &writable).ok_or_else(|| "the sandbox cannot confine commands on this machine".to_owned()),
            };
            match sandbox {
                Ok(sandbox) => sandbox.command(&program).map_err(|e| RpcError::internal(format!("cannot prepare the sandbox: {e}")))?,
                // Not a missing provider: the caller's own shell has the same sandbox.
                Err(why) => return cc_protocol::to_value(&refused(job, "sandbox", why)),
            }
        } else {
            std::process::Command::new(&program)
        };
        let script = if path.is_empty() {
            p.command.clone()
        } else {
            let dirs = path.iter().map(|dir| dir.to_string_lossy().into_owned()).collect::<Vec<_>>().join(":");
            format!("export PATH={}:\"$PATH\"\n{}", quote(&dirs), p.command)
        };
        let (reader, writer) = std::io::pipe().map_err(|e| RpcError::internal(format!("cannot open a pipe: {e}")))?;
        let second = writer.try_clone().map_err(|e| RpcError::internal(format!("cannot open a pipe: {e}")))?;
        command
            .arg("-lc")
            .arg(&script)
            .current_dir(&cwd)
            .envs(&p.env)
            .env_remove("CORTEX_FRAME_SOCKET")
            .env_remove("CORTEX_PLUGIN_INSTANCE")
            .env_remove("CORTEX_TOKEN")
            .stdin(Stdio::null())
            .stdout(writer)
            .stderr(second)
            .process_group(0);
        let mut child = command.spawn().map_err(|e| RpcError::internal(format!("cannot start {}: {e}", program.display())))?;
        drop(command);
        let pid = child.id();
        self.remember(job.clone(), Some(pid as i32));
        // The id first, so a caller that loses this call can still read the job later.
        if !p.options.background {
            items.send(json!({"kind": "job", "id": id}));
        }

        // It is a Run here like any other.
        let mut run = Run {
            id: id.clone(),
            term_id: term_id.clone(),
            command: p.command.clone(),
            cwd: cwd.to_string_lossy().into_owned(),
            started,
            format: "raw".into(),
            author: asked_by.clone(),
            ..Run::default()
        };
        if let Some(store) = &self.store {
            let session = Some(caller.session_id.clone()).filter(|s| !s.is_empty());
            store.shell(&term_id, store::ShellInfo { shell: program.to_string_lossy().into_owned(), started_ms: None, session });
            store.started(&run, self.login_path());
        }
        (self.emit)(topics::RUN_STARTED, serde_json::to_value(&run).unwrap_or(Value::Null));

        let trace = if p.options.monitor {
            let label: String = p.command.chars().take(200).collect();
            let answer = ctx.call("system.trace.run", json!({"pid": pid, "label": label, "asked_by": asked_by, "held": true})).await;
            answer.ok().and_then(|info| info["id"].as_str().map(str::to_owned))
        } else {
            None
        };
        job.trace = trace.as_ref().map(|id| format!("trace://{id}"));
        self.update(&id, |j| j.trace = job.trace.clone());
        let mut props = Map::new();
        props.insert("job_state".into(), json!("running"));
        props.insert("pgid".into(), json!(pid));
        props.insert("purpose".into(), json!(if p.options.purpose.is_empty() { "shell" } else { p.options.purpose.as_str() }));
        props.insert("trace".into(), job.trace.clone().map_or(Value::Null, Value::String));
        for (name, value) in [("caller_app", &caller.app), ("caller_node", &caller.node), ("caller_session", &caller.session_id), ("caller_by", &caller.by)] {
            props.insert(name.into(), json!(value));
        }
        self.record(&id, props);

        let me = self.clone();
        let limit = if p.timeout_ms > 0 { Duration::from_millis(p.timeout_ms) } else if p.options.background { BACKGROUND } else { TIMEOUT };
        let background = p.options.background;
        let work = async move {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
            std::thread::spawn(move || {
                let mut reader = BufReader::new(reader);
                let mut line = Vec::new();
                while reader.read_until(b'\n', &mut line).unwrap_or(0) > 0 {
                    // Escape codes and hidden characters are removed before the caller (often a
                    // model) reads the line.
                    let _ = tx.send(threat::clean(String::from_utf8_lossy(&line).trim_end_matches(['\n', '\r'])).0);
                    line.clear();
                }
            });
            let deadline = Instant::now() + limit;
            let mut tail: VecDeque<String> = VecDeque::new();
            let (mut lines, mut bytes, mut kept) = (0u64, 0u64, 0u64);
            let mut batch: Vec<store::Line> = Vec::new();
            let mut traced: Vec<(u64, String)> = Vec::new();
            let mut handed = Instant::now();
            let mut ended_why: Option<&str> = None;
            let mut watch = watch;
            let matched = |why: &str, line: &str| {
                let event = CommandMatched { id: run.id.clone(), node: caller.node.clone(), session_id: caller.session_id.clone(), why: why.into(), line: line.into() };
                (me.emit)(svc::topics::COMMAND_MATCHED, serde_json::to_value(&event).unwrap_or(Value::Null));
            };
            let status = loop {
                tokio::select! {
                    line = rx.recv() => match line {
                        Some(text) => {
                            let at = now_ms();
                            if !background {
                                items.send(json!({"kind": "output", "text": format!("{text}\n")}));
                            }
                            if let Some(watch) = &mut watch && let Some(why) = watch.line(&text) {
                                matched(why, &text);
                            }
                            if me.store.is_some() && kept < store::OUTPUT_CAP {
                                let line = store::Line { at, level: String::new(), text: text.clone(), ansi: String::new() };
                                kept += line.size();
                                batch.push(line);
                            }
                            if trace.is_some() && traced.len() < TRACE_LINES {
                                traced.push((at, text.chars().take(2000).collect()));
                            }
                            lines += 1;
                            if let Some(store) = &me.store && (batch.len() >= 500 || handed.elapsed() >= Duration::from_millis(200)) {
                                store.lines(&run.id, std::mem::take(&mut batch));
                                handed = Instant::now();
                            }
                            bytes += text.len() as u64 + 1;
                            tail.push_back(text.chars().take(400).collect());
                            if tail.len() > TAIL {
                                tail.pop_front();
                            }
                        }
                        None => match child.try_wait() {
                            Ok(Some(status)) => break Some(status),
                            _ => tokio::time::sleep(Duration::from_millis(50)).await,
                        },
                    },
                    _ = tokio::time::sleep(Duration::from_millis(200)) => {
                        if let Some(store) = &me.store && !batch.is_empty() {
                            store.lines(&run.id, std::mem::take(&mut batch));
                            handed = Instant::now();
                        }
                        if let Some(watch) = &mut watch && watch.silent() {
                            matched("silence", tail.back().map(String::as_str).unwrap_or(""));
                        }
                        if let Ok(Some(status)) = child.try_wait() {
                            // What it left running may still hold the output open: take what is there.
                            while let Ok(text) = rx.try_recv() {
                                tail.push_back(text);
                            }
                            break Some(status);
                        }
                        if Instant::now() >= deadline {
                            ended_why = Some("timed out");
                            break None;
                        }
                    }
                    _ = cancel.cancelled(), if !background => {
                        ended_why = Some("cancelled");
                        break None;
                    }
                }
            };
            let status = match status {
                Some(status) => Some(status),
                None => {
                    // SAFETY: the job runs in its own process group, created for it at spawn.
                    unsafe { libc::killpg(pid as i32, libc::SIGKILL) };
                    tokio::task::spawn_blocking(move || child.wait().ok()).await.ok().flatten()
                }
            };
            let exit_code = status.map(|s| s.code().unwrap_or_else(|| 128 + s.signal().unwrap_or(0)));
            if let Some(store) = &me.store {
                store.lines(&run.id, std::mem::take(&mut batch));
            }

            let ended = now_ms();
            run.ended = Some(ended);
            run.exit_code = exit_code;
            run.duration_ms = ended.saturating_sub(started);
            run.lines = lines;
            run.bytes = bytes;
            if let Some(store) = &me.store {
                store.finished(&run);
            }
            (me.emit)(topics::RUN_FINISHED, serde_json::to_value(&run).unwrap_or(Value::Null));

            let mut trace_line = None;
            if let Some(trace) = &trace {
                let _ = ctx.call("system.trace.stop", json!({"id": trace, "exit_code": exit_code, "output": traced})).await;
                trace_line = ctx.call("system.trace.read", json!({"id": trace, "size": "line"})).await.ok().and_then(|v| v["line"].as_str().map(str::to_owned));
            }
            let stopped = lock(&me.jobs).iter().any(|entry| entry.job.id == run.id && entry.job.state == "stopped");
            let mut job = me.job(&run.id).unwrap_or_default();
            job.state = if stopped || ended_why.is_some() { "stopped".into() } else if exit_code == Some(0) { "done".into() } else { "failed".into() };
            job.ended = Some(ended);
            job.exit_code = exit_code;
            job.duration_ms = run.duration_ms;
            job.tail = tail.into_iter().collect();
            if let Some(why) = ended_why {
                job.tail.push(format!("({why} after {} s; its processes were killed)", run.duration_ms / 1000));
            }
            job.trace_line = trace_line;
            job.text = job_text(&job);
            me.remember(job.clone(), None);
            let mut props = Map::new();
            props.insert("job_state".into(), json!(job.state));
            props.insert("job_text".into(), json!(job.text));
            props.insert("tail".into(), json!(job.tail));
            props.insert("trace_line".into(), job.trace_line.clone().map_or(Value::Null, Value::String));
            me.record(&run.id, props);
            if !caller.node.is_empty() {
                let event = CommandEnded { id: run.id.clone(), node: caller.node.clone(), session_id: caller.session_id.clone(), job: job.clone() };
                (me.emit)(svc::topics::COMMAND_ENDED, serde_json::to_value(&event).unwrap_or(Value::Null));
            }
            job
        };
        if background {
            tokio::spawn(work);
            job.text = job_text(&job);
            return cc_protocol::to_value(&job);
        }
        cc_protocol::to_value(&work.await)
    }
}

/// A refused job: it did not run; the reason is the risk engine's (or why the sandbox cannot).
fn refused(mut job: Job, risk: &str, reason: String) -> Job {
    job.state = "refused".into();
    job.ended = Some(now_ms());
    job.needs_approval = Some(NeedsApproval { risk: risk.into(), reason });
    job.text = job_text(&job);
    job
}

/// `Job.text`: a few short lines a small model reads as they are.
fn job_text(job: &Job) -> String {
    let time = duration(job.duration_ms);
    let mut lines = vec![match job.state.as_str() {
        "done" | "failed" => match job.exit_code {
            Some(code) => format!("{}: exit code {code} after {time}.", job.state),
            None => format!("{} after {time}.", job.state),
        },
        "running" => format!("running for {time}."),
        "stopped" => format!("stopped after {time}{}.", job.tail.last().filter(|l| l.starts_with('(')).map(|l| format!(" {l}")).unwrap_or_default()),
        "refused" => match &job.needs_approval {
            Some(why) => format!("refused ({}): {}. It did not run; it needs the person's approval.", why.risk, why.reason),
            None => "refused: it did not run.".into(),
        },
        "lost" => "lost: CortexTerm stopped while this ran; its result is unknown.".into(),
        other => format!("{other}."),
    }];
    if let Some(line) = job.trace_line.as_deref().filter(|line| !line.is_empty()) {
        lines.push(format!("machine: {}", line.split_once(": ").map_or(line, |(_, rest)| rest)));
    }
    let error = regex::Regex::new(r"(?i)\b(error|failed|failure|panic|fatal|exception)\b").ok();
    if let Some(first) = job.tail.iter().find(|line| error.as_ref().is_some_and(|re| re.is_match(line))) {
        lines.push(format!("first error: {}", first.chars().take(200).collect::<String>()));
    }
    if !matches!(job.state.as_str(), "refused") {
        let mut more = format!("more: terminal.command.output.read {{run_id: {}}} for the output", job.id);
        if job.trace.is_some() {
            more.push_str("; jobs.get with size summary or at <ms> for what it did to the machine");
        }
        lines.push(more);
    }
    lines.join("\n")
}

/// `850 ms`, `42 s`, `2m04s`.
fn duration(ms: u64) -> String {
    match ms {
        0..1_000 => format!("{ms} ms"),
        1_000..60_000 => format!("{} s", ms / 1_000),
        _ => format!("{}m{:02}s", ms / 60_000, ms / 1_000 % 60),
    }
}

/// The Shell a caller's commands run in: one per asking session.
fn shell_id(caller: &Caller) -> String {
    let part = |text: &str| text.chars().map(|c| if c.is_ascii_alphanumeric() || c == '-' || c == '_' { c } else { '-' }).take(64).collect::<String>();
    let mut id = "service".to_owned();
    for text in [&caller.app, &caller.session_id] {
        if !text.is_empty() {
            id.push('.');
            id.push_str(&part(text));
        }
    }
    id
}

/// The asking app's home on this machine (`~/.cortexcode`), when it has one.
fn caller_home(caller: &Caller) -> Option<PathBuf> {
    if !caller.local || caller.app.is_empty() || !caller.app.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return None;
    }
    let home = PathBuf::from(std::env::var_os("HOME")?).join(format!(".{}", caller.app));
    home.is_dir().then_some(home)
}

/// Kill a lost job's process group, only while its leader is the process the job started (the
/// group id is not reused for a newer one).
fn kill_if_ours(pgid: i32, started_ms: u64) {
    // SAFETY: getpgid only reads the process's group.
    if pgid <= 1 || unsafe { libc::getpgid(pgid) } != pgid {
        return;
    }
    let output = std::process::Command::new("ps").args(["-o", "etime=", "-p", &pgid.to_string()]).output();
    let Some(elapsed) = output.ok().and_then(|o| elapsed_s(String::from_utf8_lossy(&o.stdout).trim())) else { return };
    let began = now_ms().saturating_sub(elapsed * 1000);
    if began.abs_diff(started_ms) <= 5_000 {
        // SAFETY: the group is the job's (checked above).
        unsafe { libc::killpg(pgid, libc::SIGKILL) };
    }
}

/// `ps` elapsed time, `[[dd-]hh:]mm:ss`, in seconds.
fn elapsed_s(text: &str) -> Option<u64> {
    let (days, rest) = match text.split_once('-') {
        Some((days, rest)) => (days.parse::<u64>().ok()?, rest),
        None => (0, text),
    };
    let mut seconds = 0;
    for part in rest.split(':') {
        seconds = seconds * 60 + part.parse::<u64>().ok()?;
    }
    Some(days * 86_400 + seconds)
}

/// A background job's `watch`.
struct Watcher {
    pattern: Option<regex::Regex>,
    silence: Option<Duration>,
    last_match: Option<Instant>,
    last_line: Instant,
    told_silence: bool,
}

impl Watcher {
    fn new(watch: &svc::Watch) -> Result<Self, RpcError> {
        let pattern = match watch.pattern.as_deref().filter(|p| !p.is_empty()) {
            Some(text) => Some(regex::Regex::new(text).map_err(|e| RpcError::invalid_params(format!("watch pattern: {e}")))?),
            None => None,
        };
        Ok(Watcher { pattern, silence: watch.silence_s.filter(|s| *s > 0).map(Duration::from_secs), last_match: None, last_line: Instant::now(), told_silence: false })
    }

    /// A line came: `pattern` when it matches (at most once per 5 s).
    fn line(&mut self, text: &str) -> Option<&'static str> {
        self.last_line = Instant::now();
        self.told_silence = false;
        let hit = self.pattern.as_ref().is_some_and(|re| re.is_match(text)) && self.last_match.is_none_or(|at| at.elapsed() >= Duration::from_secs(5));
        if hit {
            self.last_match = Some(Instant::now());
        }
        hit.then_some("pattern")
    }

    /// Silent for the asked time (once per silent stretch).
    fn silent(&mut self) -> bool {
        let silent = !self.told_silence && self.silence.is_some_and(|after| self.last_line.elapsed() >= after);
        if silent {
            self.told_silence = true;
        }
        silent
    }
}

/// Under the home folder: what a script run in the sandbox may neither read nor write (keys,
/// tokens, keychains, browser profiles, wallets, notes).
#[cfg(target_os = "macos")]
const SECRET_PATHS: &[&str] = &[
    ".ssh", ".aws", ".gnupg", ".kube", ".docker", ".azure", ".config/gcloud", ".config/gh", ".netrc", ".npmrc", ".pypirc",
    ".git-credentials", "Library/Keychains", "Library/Cookies", "Library/Safari", "Library/Messages", "Library/Mail",
    "Library/Group Containers/group.com.apple.notes", "Library/Application Support/Google/Chrome",
    "Library/Application Support/BraveSoftware", "Library/Application Support/Firefox", "Library/Application Support/Microsoft Edge",
    "Library/Application Support/Arc", "Library/Application Support/com.operasoftware.Opera", "Library/Application Support/Vivaldi",
    "Library/Application Support/Exodus", "Library/Application Support/Electrum", "Library/Application Support/atomic",
];

/// The command line that runs `command` in the write sandbox (it writes only in `cwd`, the temp
/// and package-cache folders) with the secrets above out of reach and the keychain service
/// refused, for the person to run in their own terminal. The profile is a file in the plugin's
/// data folder, so the line stays short.
#[cfg(target_os = "macos")]
pub fn sandboxed_command(home: &Path, cwd: &Path, command: &str) -> Result<String, String> {
    use std::hash::{Hash, Hasher};
    let data = store::default_dir().unwrap_or_else(|| home.join("plugins-data").join("terminal"));
    let policy = Policy::new(home, &data, &[]);
    if let Some(why) = policy.unavailable() {
        return Err(format!("the sandbox cannot run here: {why}"));
    }
    let sandbox = policy.sandbox(cwd, None, &[]).ok_or("the sandbox cannot confine commands on this machine")?;
    let user = PathBuf::from(std::env::var_os("HOME").ok_or("no home folder")?);
    let mut profile = sandbox.profile.clone();
    profile.push_str("(deny file-read* file-write*\n");
    for part in SECRET_PATHS {
        let path = user.join(part);
        let path = std::fs::canonicalize(&path).unwrap_or(path);
        profile.push_str(&format!("  (subpath {:?})\n", path.to_string_lossy()));
    }
    profile.push_str(")\n(deny mach-lookup (global-name \"com.apple.SecurityServer\") (global-name \"com.apple.securityd.xpc\"))\n");
    let mut hasher = std::hash::DefaultHasher::new();
    profile.hash(&mut hasher);
    let dir = data.join("sandbox");
    std::fs::create_dir_all(&dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    let file = dir.join(format!("{:016x}.sb", hasher.finish()));
    if file.exists() {
        // In use: its time says so, so the pruning below keeps it.
        let _ = std::fs::File::options().append(true).open(&file).and_then(|f| f.set_modified(std::time::SystemTime::now()));
    } else {
        std::fs::write(&file, &profile).map_err(|e| format!("{}: {e}", file.display()))?;
        // Profiles not used for a week go.
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let stale = entry.metadata().and_then(|meta| meta.modified()).ok().and_then(|at| at.elapsed().ok()).is_some_and(|age| age.as_secs() > 7 * 86_400);
            if stale {
                let _ = std::fs::remove_file(entry.path());
            }
        }
    }
    let mut line = vec![sandbox.exec.to_string_lossy().into_owned()];
    for (key, value) in &sandbox.params {
        line.push("-D".into());
        line.push(format!("{key}={value}"));
    }
    line.extend(["-f".to_owned(), file.to_string_lossy().into_owned(), "/bin/sh".into(), "-c".into(), command.to_owned()]);
    Ok(line.iter().map(|word| quote(word)).collect::<Vec<_>>().join(" "))
}

#[cfg(not(target_os = "macos"))]
pub fn sandboxed_command(_home: &Path, _cwd: &Path, _command: &str) -> Result<String, String> {
    Err("running a script without access to secrets is only available on macOS".into())
}

/// A shell word, quoted when it has to be.
fn quote(word: &str) -> String {
    if !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "@%+=:,./~-_".contains(c)) {
        word.to_owned()
    } else {
        format!("'{}'", word.replace('\'', "'\\''"))
    }
}

/// `~` and `~/…` are the home folder.
fn expand(path: &str, home: &Path) -> PathBuf {
    let user = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| home.to_path_buf());
    match path.strip_prefix('~') {
        Some("") => user,
        Some(rest) if rest.starts_with('/') => user.join(&rest[1..]),
        _ => PathBuf::from(path),
    }
}

fn method(name: &str, description: &str, params: Value) -> SharedMethod {
    SharedMethod { method: name.into(), description: description.into(), params }
}

/// What this plugin shares.
pub fn shares() -> ShareList {
    let id = json!({"type": "object", "properties": {"id": {"type": "string", "description": "The job id (it is the Run's id)."}}, "required": ["id"]});
    let get = json!({
        "type": "object",
        "properties": {
            "id": {"type": "string", "description": "The job id (it is the Run's id)."},
            "size": {"type": "string", "enum": ["line", "summary", "series", "records"], "description": "For a traced job: its trace in this size, as `detail`."},
            "at": {"type": "integer", "description": "For a traced job: Unix milliseconds; what ran, the memory, open files and last output then, as `detail`."}
        },
        "required": ["id"]
    });
    let run = json!({
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The shell command, run in the person's login shell."},
            "cwd": {"type": "string", "description": "The folder it runs in (absolute or ~/...); in the sandbox the folder it may write."},
            "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Extra environment variables."},
            "path": {"type": "array", "items": {"type": "string"}, "description": "Folders put in front of PATH after the login profile ran (a venv's bin, toolchains)."},
            "shell": {"type": "string", "enum": ["bash"], "description": "`bash` runs it in /bin/bash; the person's own shell when absent."},
            "purpose": {"type": "string", "enum": ["check", "build", "server", "shell"], "description": "What kind of work it is: tests and linters, a build, a server that stays up, anything else."},
            "timeout_ms": {"type": "integer", "description": "Stop it after this long (10 minutes when absent)."},
            "monitor": {"type": "boolean", "description": "Record a trace of what it does to the machine (CPU, memory, processes, files, hosts)."},
            "sandboxed": {"type": "boolean", "description": "Run it in the write sandbox: writes only in cwd, temp and package caches, and `writable`."},
            "writable": {"type": "array", "items": {"type": "string"}, "description": "More folders the sandbox lets it write."},
            "background": {"type": "boolean", "description": "Answer at once and let it run (a server, a long build); read it later with jobs.get."},
            "watch": {
                "type": "object",
                "description": "For a background run: an event to the caller when a line matches `pattern` (a regular expression) or the output is silent for `silence_s` seconds.",
                "properties": {"pattern": {"type": "string"}, "silence_s": {"type": "integer"}}
            }
        },
        "required": ["command", "cwd"]
    });
    let output = json!({
        "type": "object",
        "properties": {
            "run_id": {"type": "string", "description": "The job id."},
            "from": {"type": "integer", "description": "First line (0-based); negative counts from the end (-200: the last 200)."},
            "count": {"type": "integer", "description": "How many lines (500 when absent)."},
            "filter": {"type": "string", "description": "Only lines containing this, or `level>=warn` / `level>=error`."}
        },
        "required": ["run_id"]
    });
    ShareList {
        shares: vec![Share {
            service: "terminal.command".into(),
            version: 1,
            title: "Terminal commands".into(),
            description: "Run a command on this machine in the person's own shell setup, optionally sandboxed and traced; it shows in CortexTerm as a Run.".into(),
            methods: vec![
                method("terminal.command.run", "Run a command and get its result (output streams while it runs). Risky commands come back refused with the reason until the person approves them.", run),
                method("terminal.command.stop", "Stop a running command and everything it started.", id.clone()),
                method("terminal.command.jobs.list", "The running commands and the last finished ones.", json!({"type": "object", "properties": {}})),
                method("terminal.command.jobs.get", "One command's state, exit code, last lines and trace (kept as long as its Run); with size or at, what it did to the machine.", get),
                method("terminal.command.output.read", "A command's output lines.", output),
            ],
            // For apps: each app's model runs commands with that app's own `run` tool.
            audience: Audience::Apps,
        }],
    }
}

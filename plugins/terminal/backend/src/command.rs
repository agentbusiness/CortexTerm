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

use crate::{assess, threat};
use crate::marks::ShellEnv;
use crate::store::{self, Store};
use cc_protocol::contracts::service::{Job, NeedsApproval, Share, ShareList, SharedMethod};
use cc_protocol::contracts::terminal::{CommandRunParams, Run, RunOutputParams, topics};
use cc_protocol::{Ctx, ItemSink, RpcError, codes};
use cc_sandbox_kit::sandbox::Policy;
use serde_json::{Value, json};
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
    std::env::var("SHELL").ok().filter(|s| s.starts_with('/') && Path::new(s).is_file()).map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/bin/zsh"))
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
        let asked_by = p.caller.as_ref().map(|c| c.app.clone()).filter(|app| !app.is_empty()).unwrap_or_else(|| "service".into());
        let id = format!("run-{}", uuid::Uuid::new_v4().simple());
        let started = now_ms();
        let mut job = Job { id: id.clone(), state: "running".into(), started, ..Job::default() };

        // The risk engine decides whether it may run without the person.
        let env = ShellEnv { path: self.login_path(), aliases: HashMap::new(), functions: Default::default() };
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
            job.state = "refused".into();
            job.ended = Some(now_ms());
            job.needs_approval = Some(NeedsApproval { risk: assessment.risk.clone(), reason });
            return cc_protocol::to_value(&job);
        }

        // The process: the login shell, in the sandbox when asked.
        let program = shell();
        let mut command = if p.options.sandboxed {
            let policy = self.policy();
            if let Some(why) = policy.unavailable() {
                return Err(RpcError::new(codes::UNAVAILABLE, format!("the sandbox cannot run here: {why}")));
            }
            let writable: Vec<PathBuf> = p.options.writable.iter().map(|path| expand(path, &self.home)).filter(|path| path.is_absolute()).collect();
            let sandbox = policy.sandbox(&cwd, None, &writable).ok_or_else(|| RpcError::new(codes::UNAVAILABLE, "the sandbox cannot confine commands on this machine"))?;
            sandbox.command(&program).map_err(|e| RpcError::internal(format!("cannot prepare the sandbox: {e}")))?
        } else {
            std::process::Command::new(&program)
        };
        let (reader, writer) = std::io::pipe().map_err(|e| RpcError::internal(format!("cannot open a pipe: {e}")))?;
        let second = writer.try_clone().map_err(|e| RpcError::internal(format!("cannot open a pipe: {e}")))?;
        command
            .arg("-lc")
            .arg(&p.command)
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

        // It is a Run here like any other.
        let mut run = Run {
            id: id.clone(),
            term_id: "service".into(),
            command: p.command.clone(),
            cwd: cwd.to_string_lossy().into_owned(),
            started,
            format: "raw".into(),
            author: asked_by.clone(),
            ..Run::default()
        };
        if let Some(store) = &self.store {
            store.shell("service", store::ShellInfo { shell: program.to_string_lossy().into_owned(), started_ms: None, session: None });
            store.started(&run, self.login_path());
        }
        (self.emit)(topics::RUN_STARTED, serde_json::to_value(&run).unwrap_or(Value::Null));

        let trace = if p.options.monitor {
            let label: String = p.command.chars().take(200).collect();
            let answer = ctx.call("system.trace.run", json!({"pid": pid, "label": label, "asked_by": asked_by})).await;
            answer.ok().and_then(|info| info["id"].as_str().map(str::to_owned))
        } else {
            None
        };
        job.trace = trace.as_ref().map(|id| format!("trace://{id}"));
        self.update(&id, |j| j.trace = job.trace.clone());

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
            let mut handed = Instant::now();
            let mut ended_why: Option<&str> = None;
            let status = loop {
                tokio::select! {
                    line = rx.recv() => match line {
                        Some(text) => {
                            let at = now_ms();
                            if !background {
                                items.send(json!({"kind": "output", "text": format!("{text}\n")}));
                            }
                            if me.store.is_some() && kept < store::OUTPUT_CAP {
                                let line = store::Line { at, level: String::new(), text: text.clone(), ansi: String::new() };
                                kept += line.size();
                                batch.push(line);
                            }
                            lines += 1;
                            if let Some(store) = &me.store && (batch.len() >= 500 || handed.elapsed() >= Duration::from_millis(200)) {
                                store.lines(&id, std::mem::take(&mut batch));
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
                            store.lines(&id, std::mem::take(&mut batch));
                            handed = Instant::now();
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
                let _ = ctx.call("system.trace.stop", json!({"id": trace})).await;
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
            me.remember(job.clone(), None);
            job
        };
        if background {
            tokio::spawn(work);
            return cc_protocol::to_value(&job);
        }
        cc_protocol::to_value(&work.await)
    }
}

/// Under the home folder: what a script run in the sandbox may neither read nor write (keys,
/// tokens, keychains, browser profiles, wallets, notes).
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
    if !file.exists() {
        std::fs::write(&file, &profile).map_err(|e| format!("{}: {e}", file.display()))?;
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
    let run = json!({
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The shell command, run in the person's login shell."},
            "cwd": {"type": "string", "description": "The folder it runs in (absolute or ~/...); in the sandbox the folder it may write."},
            "env": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Extra environment variables."},
            "timeout_ms": {"type": "integer", "description": "Stop it after this long (10 minutes when absent)."},
            "monitor": {"type": "boolean", "description": "Record a trace of what it does to the machine (CPU, memory, processes, files, hosts)."},
            "sandboxed": {"type": "boolean", "description": "Run it in the write sandbox: writes only in cwd, temp and package caches, and `writable`."},
            "writable": {"type": "array", "items": {"type": "string"}, "description": "More folders the sandbox lets it write."},
            "background": {"type": "boolean", "description": "Answer at once and let it run (a server, a long build); read it later with jobs.get."}
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
                method("terminal.command.jobs.get", "One command's state, exit code, last lines and trace.", id),
                method("terminal.command.output.read", "A command's output lines.", output),
            ],
        }],
    }
}

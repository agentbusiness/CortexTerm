//! `cc-system` executable: serve `system@1` to the frame. A background sampler keeps the latest
//! metrics, process snapshot and ports; watchers turn them into alerts (published and sent to the
//! notify plugin); the security sweep runs on request and as a schedule (daily by default), next
//! to the user's own scheduled commands; SSH hosts and keys are read on request.
//!
//! Everything it keeps lives in the terminal's graph (`graph`, docs/GRAPH-MODEL.md); nothing is
//! written to files. At start it waits for memory, moves in what earlier versions kept as files
//! (`migrate`), loads what each module keeps, and only then compares against baselines.

mod agents;
mod alerts;
mod ask;
mod codesign;
mod cve;
mod cvewatch;
mod deep;
mod docs;
mod feeds;
mod findings;
mod graph;
mod host;
mod intrusion;
mod inventory;
#[cfg(target_os = "macos")]
mod keychain;
mod keys;
mod launch;
mod malware;
mod migrate;
mod monitor;
mod netsec;
mod netwatch;
mod persist;
mod ports;
mod privacy;
mod posture;
mod procs;
mod sampler;
mod schedule;
mod ssh;
mod shares;
mod sweep;
mod tracer;
mod util;

use alerts::{AlertStore, Candidate};
use cc_protocol::contracts::lifecycle::{Hello, ProbeCheck, ProbeReport};
use cc_protocol::contracts::memory::{self as memory_contract, TraceAppendParams, TraceInfo};
use cc_protocol::contracts::notify::{self, Notification};
use cc_protocol::contracts::terminal::{self as terminal_contract, Run, RunOutput, ListResult as TermList};
use cc_protocol::contracts::system::{
    Alert, AskParams, AskResult, CheckParams, CveParams, KeysSetParams, Metrics, MonitorParams, MonitorReport, PortList, ProcSample, ProcessesParams, Schedule, ScheduleRun, SignalParams, SweepReport, IgnoreParams, ChangesParams, MemoryChanges, AppChange, ScheduleRunsParams, TraceReadParams, TraceStartParams, methods, topics,
};
use cc_protocol::{BoxFuture, Call, Ctx, Plugin, RpcError, parse_params, to_value};
use procs::Snapshot;
use sampler::{Power, Sampler};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

struct MemPoint {
    at: u64,
    used: u64,
    swap: u64,
    apps: HashMap<String, u64>,
}

struct Shared {
    data_dir: PathBuf,
    ctx: OnceLock<Ctx>,
    /// Loading from the graph has started (once).
    hydrating: AtomicBool,
    started: AtomicBool,
    sampler: Mutex<Option<Sampler>>,
    metrics: Mutex<Metrics>,
    snapshot: Mutex<Arc<Snapshot>>,
    ports: Mutex<PortList>,
    power: Arc<Mutex<Power>>,
    alerts: Mutex<AlertStore>,
    /// The last sweep and every finding's state (ignored ones included), as the graph holds them.
    findings: Mutex<findings::Store>,
    /// Memory every 30 s for the last 30 minutes: what "why did my memory go down" is answered from.
    memory_log: Mutex<std::collections::VecDeque<MemPoint>>,
    sweep_lock: tokio::sync::Mutex<()>,
    /// pid -> one reading a scan, the last 20 minutes (what the Investigate charts draw).
    history: Mutex<HashMap<u32, std::collections::VecDeque<ProcSample>>>,
    /// pid -> monitor mode, on or ended (its log kept until it is started again).
    monitors: Mutex<HashMap<u32, monitor::Monitor>>,
    ssh: ssh::State,
    schedules: Mutex<schedule::Store>,
    /// The traces recording now (their records go to memory every few seconds).
    tracer: Mutex<tracer::Tracer>,
    /// One flush to memory at a time.
    flushing: tokio::sync::Mutex<()>,
    /// Terminal id -> its shell's pid.
    shells: Mutex<HashMap<String, u32>>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Shared {
    fn new() -> Self {
        let data_dir = util::data_dir();
        Shared {
            alerts: Mutex::new(AlertStore::default()),
            findings: Mutex::new(findings::Store::default()),
            memory_log: Mutex::new(Default::default()),
            schedules: Mutex::new(schedule::Store::default()),
            tracer: Mutex::new(tracer::Tracer::default()),
            hydrating: AtomicBool::new(false),
            flushing: tokio::sync::Mutex::new(()),
            shells: Mutex::new(HashMap::new()),
            ssh: ssh::State::default(),
            data_dir,
            ctx: OnceLock::new(),
            started: AtomicBool::new(false),
            sampler: Mutex::new(None),
            metrics: Mutex::new(Metrics::default()),
            snapshot: Mutex::new(Arc::new(Snapshot::default())),
            ports: Mutex::new(PortList::default()),
            power: Arc::new(Mutex::new(Power::default())),
            sweep_lock: tokio::sync::Mutex::new(()),
            history: Mutex::new(HashMap::new()),
            monitors: Mutex::new(HashMap::new()),
        }
    }

    /// One sampler tick (blocking): store the results, return the watchers' candidates.
    fn tick(&self) -> (Metrics, Vec<Candidate>) {
        let power = *lock(&self.power);
        let mut slot = lock(&self.sampler);
        let sampler = slot.get_or_insert_with(Sampler::new);
        let (metrics, found) = sampler.tick(power);
        if sampler.snapshot.at != lock(&self.snapshot).at {
            *lock(&self.snapshot) = Arc::new(sampler.snapshot.clone());
            self.keep_history(&sampler.snapshot);
            lock(&self.tracer).scan(&sampler.snapshot);
        }
        lock(&self.ports).ports = sampler.ports.clone();
        *lock(&self.metrics) = metrics.clone();
        self.log_memory(&metrics, &sampler.snapshot);
        (metrics, found)
    }

    /// One reading per process per scan, 20 minutes of them; ended processes are dropped.
    fn keep_history(&self, snapshot: &procs::Snapshot) {
        const KEEP: usize = 300;
        let mut history = lock(&self.history);
        let alive: std::collections::HashSet<u32> = snapshot.entries.iter().map(|e| e.proc.pid).collect();
        history.retain(|pid, _| alive.contains(pid));
        for entry in &snapshot.entries {
            let p = &entry.proc;
            let list = history.entry(p.pid).or_default();
            list.push_back(ProcSample { at: snapshot.at, cpu: p.cpu, memory: p.memory, gpu: p.gpu, disk_write: p.disk_write });
            if list.len() > KEEP {
                list.pop_front();
            }
        }
    }

    /// Start or stop monitor mode for one process.
    fn set_monitor(&self, params: &MonitorParams) -> Result<MonitorReport, RpcError> {
        let mut monitors = lock(&self.monitors);
        if params.on {
            if !self.snapshot().entries.iter().any(|e| e.proc.pid == params.pid) {
                return Err(RpcError::not_found(format!("no process with pid {}", params.pid)));
            }
            let running = monitors.get(&params.pid).is_some_and(|m| m.report.on && m.report.children == params.children);
            if !running {
                monitors.insert(params.pid, monitor::Monitor::new(params.pid, params.children));
            }
        } else if let Some(monitor) = monitors.get_mut(&params.pid) {
            monitor.stop("");
        }
        monitors.get(&params.pid).map(|m| m.report.clone()).ok_or_else(|| RpcError::not_found(format!("pid {} is not monitored", params.pid)))
    }

    /// One read of every monitored process (blocking: runs lsof once for all of them).
    fn poll_monitors(&self) {
        let snapshot = self.snapshot();
        let alive: std::collections::HashSet<u32> = snapshot.entries.iter().map(|e| e.proc.pid).collect();
        let plan: Vec<(u32, Vec<u32>)> = {
            let mut monitors = lock(&self.monitors);
            for monitor in monitors.values_mut() {
                if monitor.report.on && !alive.contains(&monitor.report.pid) {
                    monitor.stop("The process ended.");
                }
            }
            monitors.values().filter(|m| m.report.on).map(|m| (m.report.pid, m.pids(&snapshot))).collect()
        };
        let traced = lock(&self.tracer).file_pids();
        if plan.is_empty() && traced.is_empty() {
            return;
        }
        let mut every: Vec<u32> = plan.iter().flat_map(|(_, pids)| pids.iter().copied()).chain(traced).collect();
        every.sort_unstable();
        every.dedup();
        let read = host::open_files(&every);
        lock(&self.tracer).files(&read);
        let mut monitors = lock(&self.monitors);
        for (root, pids) in plan {
            let mine = pids.iter().filter_map(|pid| read.get(pid).map(|files| (*pid, files.clone()))).collect();
            if let Some(monitor) = monitors.get_mut(&root) {
                monitor.poll(mine);
            }
        }
    }

    /// Keep one memory point per 30 s (per app, helpers summed), 30 minutes of them.
    fn log_memory(&self, metrics: &Metrics, snapshot: &procs::Snapshot) {
        let mut log = lock(&self.memory_log);
        if log.back().is_some_and(|last| metrics.at < last.at + 30_000) || snapshot.entries.is_empty() {
            return;
        }
        let mut apps: HashMap<String, u64> = HashMap::new();
        for entry in &snapshot.entries {
            let app = procs::app_of(&entry.exe, &entry.proc.name, entry.proc.pid, entry.uid);
            *apps.entry(app).or_default() += entry.proc.memory;
        }
        log.push_back(MemPoint { at: metrics.at, used: metrics.memory_used, swap: metrics.swap_used, apps });
        while log.len() > 60 {
            log.pop_front();
        }
    }

    fn memory_changes(&self, minutes: u32) -> MemoryChanges {
        let log = lock(&self.memory_log);
        let (Some(now), Some(_)) = (log.back(), log.front()) else { return MemoryChanges::default() };
        let from = if minutes == 0 { 0 } else { now.at.saturating_sub(u64::from(minutes.min(30)) * 60_000) };
        let window: Vec<&MemPoint> = log.iter().filter(|point| point.at >= from).collect();
        let then = window.first().copied().unwrap_or(now);
        let peak = window.iter().max_by_key(|point| point.used).copied().unwrap_or(now);
        let mut apps: Vec<AppChange> = then.apps.keys().chain(now.apps.keys()).collect::<std::collections::HashSet<_>>().into_iter()
            .map(|app| AppChange { app: app.clone(), then: then.apps.get(app).copied().unwrap_or(0), now: now.apps.get(app).copied().unwrap_or(0) })
            .filter(|change| change.then.abs_diff(change.now) >= 50_000_000)
            .collect();
        apps.sort_by_key(|change| std::cmp::Reverse(change.then.abs_diff(change.now)));
        apps.truncate(10);
        MemoryChanges { since: then.at, used_then: then.used, used_now: now.used, swap_then: then.swap, swap_now: now.swap, peak: peak.used, peak_at: peak.at, apps }
    }

    /// Offer a candidate; when it fires, publish it and hand it to the notify plugin. True when
    /// it fired.
    fn fire(&self, candidate: Candidate) -> bool {
        let key = candidate.key.clone();
        let about = about_of(&key);
        let Some(alert) = lock(&self.alerts).offer(candidate, about) else { return false };
        let Some(ctx) = self.ctx.get().cloned() else { return true };
        ctx.publish(topics::ALERT, serde_json::to_value(&alert).unwrap_or(Value::Null));
        let notification = Notification {
            kind: notify::kinds::INFO.into(),
            title: title_of(&alert).into(),
            body: alert.text.clone(),
            key: Some(format!("system:{key}")),
            project_id: None,
            session_id: None,
            target: json!({"open": "system.alert", "id": alert.id}),
            actions: Vec::new(),
            subtitle: None,
        };
        tokio::spawn(async move {
            let Ok(params) = to_value(&notification) else { return };
            match tokio::time::timeout(Duration::from_secs(20), ctx.call(notify::methods::SEND, params)).await {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => tracing::info!("notify.send failed: {error}"),
                Err(_) => tracing::info!("notify.send did not answer"),
            }
        });
        true
    }

    fn snapshot(&self) -> Arc<Snapshot> {
        lock(&self.snapshot).clone()
    }

    /// Run the sweep (one at a time) and store its report (in the graph, with what it saw).
    async fn run_sweep(self: &Arc<Self>) -> SweepReport {
        let _guard = self.sweep_lock.lock().await;
        // Its baselines are in the graph: wait a little for memory when it is still starting.
        graph::wait_ready(Duration::from_secs(60)).await;
        let (report, seen) = sweep::run_sweep().await;
        let mut store = lock(&self.findings);
        if graph::ready() {
            store.record(&report, seen);
        } else {
            store.last = report.clone();
        }
        let ignored = store.ignored();
        drop(store);
        sweep::mark(report, &ignored)
    }

    /// The report with the ignored findings marked (older reports get their keys here).
    fn marked(&self, report: SweepReport) -> SweepReport {
        sweep::mark(report, &lock(&self.findings).ignored())
    }

    /// Some areas' checks, apart from the stored sweep (which they fall back on when late). What
    /// they saw of this Mac is written; the stored sweep stays as it is.
    async fn check(&self, params: CheckParams) -> Result<SweepReport, RpcError> {
        let areas = sweep::Area::parse(&params.areas).map_err(RpcError::invalid_params)?;
        graph::wait_ready(Duration::from_secs(5)).await;
        let last = lock(&self.findings).last.clone();
        let within = params.within_s.map(|s| Duration::from_secs(u64::from(s.max(1))));
        let (report, seen) = sweep::run_areas(&areas, within, &last).await;
        if graph::ready() {
            graph::put(seen);
        }
        Ok(self.marked(report))
    }

    fn ignore(&self, key: String, ignore: bool) -> Result<SweepReport, RpcError> {
        let mut store = lock(&self.findings);
        store.ignore(&key, ignore).map_err(RpcError::invalid_params)?;
        let report = store.last.clone();
        drop(store);
        Ok(self.marked(report))
    }

    /// Load everything kept from the graph, once memory answers: move the old files in first,
    /// then each module's state. Until this is done nothing is compared or written.
    async fn hydrate(self: Arc<Self>) {
        let Some(ctx) = self.ctx.get().cloned() else { return };
        graph::connect(ctx).await;
        let moved = migrate::run().await;
        if !moved.counts.is_empty() {
            tracing::warn!("moved into the graph: {:?}", moved.counts);
        }
        loop {
            let started = Instant::now();
            match self.load_all().await {
                Ok(summary) => {
                    tracing::warn!("loaded from the graph in {} ms: {summary}", started.elapsed().as_millis());
                    break;
                }
                Err(error) => {
                    tracing::warn!("cannot load from the graph yet ({error}); trying again");
                    tokio::time::sleep(Duration::from_secs(10)).await;
                }
            }
        }
        graph::set_ready();
        let early = lock(&self.alerts).take_early();
        for candidate in early {
            self.fire(candidate);
        }
    }

    async fn load_all(&self) -> Result<String, String> {
        let findings = findings::Store::load().await?;
        let alerts = AlertStore::load().await?;
        let schedules = schedule::Store::load().await?;
        let recordings = tracer::load_recordings().await?;
        let feeds = docs::load_index().await?;
        let items = persist::load().await?;
        let networks = netsec::load().await?;
        let servers = agents::load().await?;
        let notes = netwatch::load_digest().await?;
        let ports = sampler::load_ports().await?;
        let summary = format!(
            "last sweep {} ({} findings), {} alerts, {} schedules, {} live traces, {feeds} feeds, {items} start items, {networks} networks, {servers} MCP servers, {notes} network notes, {ports} ports",
            findings.last.at,
            findings.last.findings.len(),
            alerts.list().alerts.len(),
            schedules.list().schedules.len(),
            recordings.len(),
        );
        *lock(&self.findings) = findings;
        lock(&self.alerts).replace(alerts);
        *lock(&self.schedules) = schedules;
        lock(&self.tracer).restore(recordings);
        Ok(summary)
    }

    /// Run one schedule now: record the result, publish it, and alert when it failed or its
    /// output matched `alert_on`.
    async fn run_schedule(self: &Arc<Self>, id: &str) -> Result<ScheduleRun, RpcError> {
        let job = lock(&self.schedules).begin(id)?;
        let started = std::time::Instant::now();
        let at = util::now_ms();
        let needle = job.alert_on.to_lowercase();
        let mut trace: Option<String> = None;
        let mut sweep_at = None;
        let (exit_code, tail, matched, timed_out) = if job.kind == "sweep" {
            let mut report = self.run_sweep().await;
            sweep_at = graph::ready().then_some(report.at);
            report.findings.retain(|finding| !finding.ignored);
            let mut tail = vec![format!(
                "{} after checking {}",
                util::plural(report.findings.len(), "finding", "findings"),
                report.checked.join(", ")
            )];
            tail.extend(report.findings.iter().map(|f| format!("[{}] {}", f.severity, f.text)));
            tail.extend(report.skipped.iter().map(|s| format!("skipped: {s}")));
            let matched = !needle.is_empty() && tail.iter().any(|line| line.to_lowercase().contains(&needle));
            tail.truncate(40);
            (0, tail, matched, false)
        } else {
            // Every run is traced: its processes while it runs, then its whole output.
            let command = job.clone();
            let me = self.clone();
            let slot: Arc<Mutex<Option<String>>> = Arc::default();
            let started_trace = slot.clone();
            let outcome = tokio::task::spawn_blocking(move || {
                schedule::run_command(&command, |pid| {
                    let seed = TraceInfo {
                        pid,
                        label: command.name.clone(),
                        command: command.command.clone(),
                        cwd: command.cwd.clone(),
                        source: "schedule".into(),
                        run_id: Some(format!("schedule:{}", command.id)),
                        ..Default::default()
                    };
                    let info = lock(&me.tracer).start_job(seed);
                    *lock(&started_trace) = Some(info.id);
                })
            })
            .await
            .unwrap_or_else(|e| schedule::Outcome { exit_code: -1, tail: vec![e.to_string()], matched: false, timed_out: false, lines: Vec::new() });
            trace = lock(&slot).clone();
            if let Some(id) = &trace {
                lock(&self.tracer).finish(id, util::now_ms(), Some(outcome.exit_code), outcome.lines);
                self.flush_traces().await;
            }
            (outcome.exit_code, outcome.tail, outcome.matched, outcome.timed_out)
        };
        let text = if timed_out {
            Some(format!("The scheduled job “{}” did not finish within 10 minutes and was stopped.", job.name))
        } else if exit_code != 0 {
            Some(format!("The scheduled job “{}” failed with exit code {exit_code}.", job.name))
        } else if matched {
            Some(format!("The output of the scheduled job “{}” contains “{}”.", job.name, job.alert_on))
        } else {
            None
        };
        let alerted = text.is_some_and(|text| {
            self.fire(Candidate {
                key: format!("schedule:{}", job.id),
                alert: Alert { kind: "schedule".into(), severity: "warn".into(), text, actions: vec!["show".into()], ..Default::default() },
            })
        });
        let run = ScheduleRun {
            id: job.id.clone(),
            name: job.name.clone(),
            at,
            duration_ms: started.elapsed().as_millis() as u64,
            exit_code,
            tail,
            alerted,
            trace,
        };
        lock(&self.schedules).finish(run.clone(), sweep_at);
        if let Some(ctx) = self.ctx.get() {
            ctx.publish(topics::SCHEDULE_DONE, serde_json::to_value(&run).unwrap_or(Value::Null));
        }
        Ok(run)
    }
}

impl Shared {
    /// Send what the traces recorded to memory. What memory does not take goes back and is
    /// sent next time.
    async fn flush_traces(&self) {
        let Some(ctx) = self.ctx.get().cloned() else { return };
        let _one = self.flushing.lock().await;
        let batches = lock(&self.tracer).take();
        for (trace, records) in batches {
            let mut sent = 0;
            while sent < records.len() || (sent == 0 && records.is_empty()) {
                let chunk: Vec<_> = records[sent..(sent + 2000).min(records.len())].to_vec();
                let params = to_value(&TraceAppendParams { trace: trace.clone(), records: chunk.clone() }).unwrap_or(Value::Null);
                match tokio::time::timeout(Duration::from_secs(30), ctx.call(memory_contract::methods::TRACE_APPEND, params)).await {
                    Ok(Ok(_)) => {}
                    outcome => {
                        let error = match outcome {
                            Ok(Err(error)) => error.to_string(),
                            _ => "no answer in 30 s".into(),
                        };
                        tracing::info!("memory.trace.append {}: {error}", trace.id);
                        lock(&self.tracer).put_back(trace.clone(), records[sent..].to_vec());
                        break;
                    }
                }
                if records.is_empty() {
                    break;
                }
                sent += chunk.len();
            }
        }
    }

    /// The pid of a terminal's shell (asked of the terminal plugin once).
    async fn shell_of(&self, term_id: &str) -> Option<u32> {
        if let Some(pid) = lock(&self.shells).get(term_id) {
            return Some(*pid);
        }
        let ctx = self.ctx.get()?.clone();
        let list = tokio::time::timeout(Duration::from_secs(5), ctx.call(terminal_contract::methods::LIST, json!({}))).await.ok()?.ok()?;
        let list: TermList = serde_json::from_value(list).ok()?;
        let mut shells = lock(&self.shells);
        for term in list.terminals {
            shells.insert(term.term_id, term.pid);
        }
        shells.get(term_id).copied()
    }

    /// A terminal's command started or finished.
    async fn on_run(&self, topic: &str, run: Run) {
        if topic == terminal_contract::topics::RUN_STARTED {
            if run.fullscreen {
                return;
            }
            let Some(shell) = self.shell_of(&run.term_id).await else { return };
            lock(&self.tracer).run_started(&run.id, &run.command, &run.cwd, run.started, shell);
            return;
        }
        // Its output, the last 2,000 lines, read only when a trace was kept.
        let ended = run.ended.unwrap_or_else(util::now_ms);
        let id = lock(&self.tracer).run_finished(&run.id, ended, run.exit_code, Vec::new());
        let Some(id) = id else { return };
        if let Some(ctx) = self.ctx.get().cloned() {
            let params = json!({"run_id": run.id, "from": -2000, "count": 2000});
            if let Ok(Ok(output)) = tokio::time::timeout(Duration::from_secs(10), ctx.call(terminal_contract::methods::RUN_OUTPUT, params)).await
                && let Ok(output) = serde_json::from_value::<RunOutput>(output)
            {
                let lines = output.lines.into_iter().map(|line| (if line.at == 0 { ended } else { line.at }, line.text)).collect();
                lock(&self.tracer).add_output(&id, lines);
            }
        }
        self.flush_traces().await;
    }

    /// Ask memory, after sending what is recorded so far.
    async fn ask_memory(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        self.flush_traces().await;
        let ctx = self.ctx.get().cloned().ok_or_else(|| RpcError::internal("not connected to the frame"))?;
        ctx.call(method, params).await
    }
}

fn title_of(alert: &Alert) -> &'static str {
    match alert.kind.as_str() {
        "cpu" => "A process is using a lot of CPU",
        "memory" => "A process keeps growing",
        "disk" => "The disk is filling up",
        "port" => "A new port is open to the network",
        "persistence" => "A new launch item",
        "unsigned" => "An unsigned program is running",
        "schedule" => "A scheduled job needs a look",
        "agent" => "An AI tool runs without asking",
        "cve" => "A known vulnerability affects this Mac",
        "network" => "A program's network activity needs a look",
        "lan" => "Your network changed",
        _ => "System",
    }
}

/// What an alert is about in the graph, from its key: an advisory, a start item.
fn about_of(key: &str) -> Option<cc_protocol::contracts::memory::GraphRef> {
    if let Some(id) = key.strip_prefix("cve:") {
        return Some(graph::r("Advisory", id));
    }
    if let Some(plist) = key.strip_prefix("persistence:") {
        let item = persist::launch_key(std::path::Path::new(plist));
        return persist::known(&item).then(|| graph::r("StartItem", item));
    }
    None
}

/// Start the sampler, macmon, the launch-folder watcher and the scheduler (once).
fn start(shared: &Arc<Shared>) {
    if shared.started.swap(true, Ordering::SeqCst) {
        return;
    }
    if !shared.hydrating.swap(true, Ordering::SeqCst) {
        tokio::spawn(shared.clone().hydrate());
    }
    sampler::spawn_power(shared.power.clone());

    // AI tools started with their permission prompts off, from the sampler's process snapshot.
    if let Some(ctx) = shared.ctx.get() {
        agents::connect(ctx);
    }
    let s = shared.clone();
    tokio::spawn(async move {
        let mut seen = std::collections::HashSet::new();
        let mut every = tokio::time::interval(Duration::from_secs(5));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            let snapshot = s.snapshot();
            let Ok((found, kept)) = tokio::task::spawn_blocking(move || (agents::watch(&snapshot, &mut seen), seen)).await else { break };
            seen = kept;
            for candidate in found {
                s.fire(candidate);
            }
        }
    });

    let s = shared.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(2));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            let worker = s.clone();
            let Ok((metrics, found)) = tokio::task::spawn_blocking(move || worker.tick()).await else { continue };
            if let Some(ctx) = s.ctx.get() {
                ctx.publish(topics::SAMPLE, serde_json::to_value(&metrics).unwrap_or(Value::Null));
            }
            for candidate in found {
                s.fire(candidate);
            }
        }
    });

    let s = shared.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(2));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            let worker = s.clone();
            let _ = tokio::task::spawn_blocking(move || worker.poll_monitors()).await;
        }
    });

    let s = shared.clone();
    tokio::spawn(async move {
        let mut every = tokio::time::interval(Duration::from_secs(4));
        every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            every.tick().await;
            s.flush_traces().await;
        }
    });

    let s = shared.clone();
    tokio::spawn(async move { watch_launch_folders(s).await });

    // The CVE watch: new exploited advisories checked against this Mac, kept in the graph.
    let (a, b) = (shared.clone(), shared.clone());
    tokio::spawn(cvewatch::run(move || a.ctx.get().cloned(), move |candidate| {
        b.fire(candidate);
    }));

    // The network watcher: connections, threat lists and this Mac's network.
    let (a, b, c) = (shared.clone(), shared.clone(), shared.clone());
    tokio::spawn(netwatch::run(move || a.snapshot(), move || lock(&b.tracer).run_pids(), move |candidate| {
        c.fire(candidate);
    }));

    let s = shared.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_secs(15)).await;
            let due = lock(&s.schedules).due(util::now_ms());
            for id in due {
                let s = s.clone();
                tokio::spawn(async move {
                    if let Err(error) = s.run_schedule(&id).await {
                        tracing::info!("schedule {id}: {error}");
                    }
                });
            }
        }
    });
}

/// New or changed plists in the launch folders become `persistence` alerts.
async fn watch_launch_folders(shared: Arc<Shared>) {
    use notify_fs::{EventKind, RecursiveMode, Watcher};
    let folders: Vec<PathBuf> = launch::folders().into_iter().filter(|d| d.is_dir()).collect();
    if folders.is_empty() {
        return;
    }
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<PathBuf>();
    let watcher = notify_fs::recommended_watcher(move |event: notify_fs::Result<notify_fs::Event>| {
        if let Ok(event) = event
            && matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_))
        {
            for path in event.paths {
                if path.extension().is_some_and(|e| e == "plist") {
                    let _ = tx.send(path);
                }
            }
        }
    });
    let mut watcher = match watcher {
        Ok(watcher) => watcher,
        Err(error) => {
            tracing::warn!("cannot watch the launch folders: {error}");
            return;
        }
    };
    for folder in &folders {
        if let Err(error) = watcher.watch(folder, RecursiveMode::NonRecursive) {
            tracing::warn!("cannot watch {}: {error}", folder.display());
        }
    }
    while let Some(first) = rx.recv().await {
        // Let the writer finish and collect the burst of events one save makes.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let mut paths = std::collections::BTreeSet::from([first]);
        while let Ok(path) = rx.try_recv() {
            paths.insert(path);
        }
        for path in paths {
            if !path.is_file() {
                continue;
            }
            let Ok(Some(item)) = tokio::task::spawn_blocking(move || launch::inspect(&path)).await else { continue };
            let severity = if item.unsigned() || item.quarantined {
                "high"
            } else if item.signature == "missing" || item.signature == "unknown" {
                "warn"
            } else {
                "info"
            };
            let program = if item.program.is_empty() { "no program we can find".to_owned() } else { item.program.clone() };
            let verdict = if item.program.is_empty() { String::new() } else { format!(", {}", item.verdict()) };
            shared.fire(Candidate {
                key: format!("persistence:{}", item.plist.display()),
                alert: Alert {
                    kind: "persistence".into(),
                    severity: severity.into(),
                    text: format!(
                        "The {} {} was added or changed in {} and starts {program}{verdict}.",
                        item.what(),
                        item.label,
                        item.folder()
                    ),
                    path: Some(item.plist.display().to_string()),
                    actions: vec!["show".into()],
                    ..Default::default()
                },
            });
        }
    }
    drop(watcher);
}

#[derive(Deserialize)]
struct PidParams {
    pid: u32,
}

#[derive(Deserialize)]
struct IdParams {
    id: String,
}

#[derive(Deserialize)]
struct ActParams {
    id: String,
    action: String,
}

async fn dispatch(shared: Arc<Shared>, method: &str, params: Value) -> Result<Value, RpcError> {
    match method {
        methods::METRICS => to_value(&*lock(&shared.metrics)),
        methods::PROCESSES => {
            let params: ProcessesParams = if params.is_null() { ProcessesParams::default() } else { parse_params(params)? };
            to_value(&procs::list(&shared.snapshot(), &params))
        }
        methods::PROCESS => {
            let PidParams { pid } = parse_params(params)?;
            let snapshot = shared.snapshot();
            let history = lock(&shared.history).get(&pid).map(|list| list.iter().cloned().collect()).unwrap_or_default();
            let monitor = lock(&shared.monitors).get(&pid).map(|m| m.report.clone());
            let detail = tokio::task::spawn_blocking(move || procs::detail(&snapshot, pid, history, monitor))
                .await
                .map_err(|e| RpcError::internal(e.to_string()))??;
            to_value(&detail)
        }
        methods::MONITOR => {
            let params: MonitorParams = parse_params(params)?;
            to_value(&shared.set_monitor(&params)?)
        }
        methods::SIGNAL => {
            let params: SignalParams = parse_params(params)?;
            procs::signal(&shared.snapshot(), &params)
        }
        methods::PORTS => to_value(&*lock(&shared.ports)),
        methods::ALERTS => to_value(&lock(&shared.alerts).list()),
        methods::ALERT_ACT => {
            let ActParams { id, action } = parse_params(params)?;
            lock(&shared.alerts).act(&id, &action).map_err(RpcError::invalid_params)?;
            Ok(json!({"ok": true}))
        }
        methods::SWEEP => {
            graph::wait_ready(Duration::from_secs(20)).await;
            let report = lock(&shared.findings).last.clone();
            if report.at != 0 {
                return to_value(&shared.marked(report));
            }
            drop(shared.sweep_lock.lock().await);
            let report = lock(&shared.findings).last.clone();
            if report.at != 0 {
                return to_value(&shared.marked(report));
            }
            to_value(&shared.run_sweep().await)
        }
        methods::SWEEP_RUN => to_value(&shared.run_sweep().await),
        methods::CHECK => to_value(&shared.check(parse_params(params)?).await?),
        methods::KEYS_SET => {
            let KeysSetParams { name, value } = parse_params(params)?;
            tokio::task::spawn_blocking(move || keys::set(&name, &value)).await.map_err(|e| RpcError::internal(e.to_string()))?.map_err(RpcError::invalid_params)?;
            to_value(&keys::status())
        }
        methods::KEYS_STATUS => to_value(&tokio::task::spawn_blocking(keys::status).await.map_err(|e| RpcError::internal(e.to_string()))?),
        methods::CVE => {
            let CveParams { id } = parse_params(params)?;
            to_value(&cve::report(&id).await.map_err(RpcError::invalid_params)?)
        }
        methods::ASK => {
            let AskParams { args, notes } = parse_params(params)?;
            let (text, exit_code) = match ask::parse(&args) {
                Err(error) => (format!("macsec: {error}\n{}\n", ask::USAGE), 2),
                Ok(ask::Request::Help) => (format!("{}\n", ask::USAGE), 0),
                Ok(ask::Request::Areas) => (ask::areas_text(), 0),
                Ok(ask::Request::Check { areas, within }) => {
                    let names = areas.iter().map(|a| a.name().to_owned()).collect();
                    let report = shared.check(CheckParams { areas: names, within_s: within.map(|w| w.as_secs() as u32) }).await?;
                    (ask::check_answer(&areas, &report, notes.as_deref()), 0)
                }
                Ok(ask::Request::Cve(id)) => match cve::report(&id).await {
                    Ok(report) => (ask::cve_text(&report), 0),
                    Err(error) => (format!("macsec: {error}\n"), 2),
                },
            };
            to_value(&AskResult { text, exit_code })
        }
        methods::MEMORY_CHANGES => {
            let ChangesParams { minutes } = parse_params(params)?;
            to_value(&shared.memory_changes(minutes))
        }
        methods::FINDING_IGNORE => {
            let IgnoreParams { key, ignore } = parse_params(params)?;
            to_value(&shared.ignore(key, ignore)?)
        }
        methods::TIMELINE => {
            let params: cc_protocol::contracts::system::TimelineParams = if params.is_null() { Default::default() } else { parse_params(params)? };
            let snapshot = shared.snapshot();
            let monitor = params.pid.and_then(|pid| lock(&shared.monitors).get(&pid).map(|m| m.report.clone()));
            let timeline = tokio::task::spawn_blocking(move || intrusion::timeline(&params, &snapshot, monitor.as_ref()))
                .await
                .map_err(|e| RpcError::internal(e.to_string()))?;
            to_value(&timeline)
        }
        methods::SSH_HOSTS => {
            let s = shared.clone();
            to_value(&tokio::task::spawn_blocking(move || s.ssh.hosts()).await.map_err(|e| RpcError::internal(e.to_string()))?)
        }
        methods::SSH_KEYS => {
            let s = shared.clone();
            to_value(&tokio::task::spawn_blocking(move || s.ssh.keys()).await.map_err(|e| RpcError::internal(e.to_string()))?)
        }
        methods::SHARES => to_value(&shares::shares()),
        methods::SCHEDULE_LIST => to_value(&lock(&shared.schedules).list()),
        methods::SCHEDULE_GET => {
            let IdParams { id } = parse_params(params)?;
            lock(&shared.schedules).list().schedules.into_iter().find(|s| s.id == id).map(|s| to_value(&s)).unwrap_or_else(|| Err(RpcError::not_found(format!("no schedule {id}"))))
        }
        methods::SCHEDULE_CREATE | methods::SCHEDULE_EDIT | methods::SCHEDULE_DELETE if !graph::ready() => {
            Err(RpcError::new(cc_protocol::codes::UNAVAILABLE, "schedules are kept in memory, which is not reachable yet; try again in a moment").retryable())
        }
        methods::SCHEDULE_CREATE => {
            let mut schedule: Schedule = parse_params(params)?;
            schedule.id.clear();
            to_value(&lock(&shared.schedules).put(schedule)?)
        }
        methods::SCHEDULE_EDIT => {
            let schedule: Schedule = parse_params(params)?;
            if schedule.id.is_empty() {
                return Err(RpcError::invalid_params("which schedule: `id` is needed"));
            }
            to_value(&lock(&shared.schedules).put(schedule)?)
        }
        methods::SCHEDULE_RUNS_LIST => {
            let p: ScheduleRunsParams = if params.is_null() { ScheduleRunsParams::default() } else { parse_params(params)? };
            let list = shared.ask_memory(memory_contract::methods::TRACE_LIST, json!({"limit": 1000})).await?;
            let want = if p.id.is_empty() { "schedule:".to_owned() } else { format!("schedule:{}", p.id) };
            let limit = if p.limit == 0 { 50 } else { p.limit as usize };
            let runs: Vec<Value> = list["traces"].as_array().into_iter().flatten()
                .filter(|t| t["run_id"].as_str().is_some_and(|r| if p.id.is_empty() { r.starts_with(&want) } else { r == want }))
                .take(limit).cloned().collect();
            Ok(json!({"traces": runs}))
        }
        methods::SCHEDULE_RUNS_READ => {
            let p: TraceReadParams = parse_params(params)?;
            let info = shared.ask_memory(memory_contract::methods::TRACE_SUMMARY, json!({"id": p.id})).await?;
            if !info["trace"]["run_id"].as_str().is_some_and(|r| r.starts_with("schedule:")) {
                return Err(RpcError::not_found(format!("{} is not a scheduled run", p.id)));
            }
            read_trace(&shared, p).await
        }
        methods::SCHEDULE_DELETE => {
            let IdParams { id } = parse_params(params)?;
            lock(&shared.schedules).delete(&id)?;
            Ok(json!({"ok": true}))
        }
        methods::SCHEDULE_RUN => {
            let IdParams { id } = parse_params(params)?;
            to_value(&shared.run_schedule(&id).await?)
        }
        methods::TRACE_RUN => {
            let p: TraceStartParams = parse_params(params.clone())?;
            let asked_by = if p.asked_by.is_empty() { caller_of(&params) } else { p.asked_by.clone() };
            let info = lock(&shared.tracer).start(&shared.snapshot(), p.pid, &p.label, &asked_by).map_err(RpcError::not_found)?;
            shared.flush_traces().await;
            to_value(&info)
        }
        methods::TRACE_STOP => {
            let IdParams { id } = parse_params(params)?;
            let stopped: Option<TraceInfo> = lock(&shared.tracer).stop(&id);
            shared.flush_traces().await;
            match stopped {
                Some(info) => to_value(&info),
                None => shared.ask_memory(memory_contract::methods::TRACE_SUMMARY, json!({"id": id})).await.map(|summary| summary["trace"].clone()),
            }
        }
        methods::TRACE_DELETE => {
            let IdParams { id } = parse_params(params.clone())?;
            if lock(&shared.tracer).is_live(&id) {
                lock(&shared.tracer).stop(&id);
            }
            shared.ask_memory(memory_contract::methods::TRACE_DELETE, json!({"id": id})).await
        }
        methods::TRACE_LIST => {
            let limit = params.get("limit").and_then(Value::as_u64).unwrap_or(0);
            shared.ask_memory(memory_contract::methods::TRACE_LIST, json!({"limit": limit})).await
        }
        methods::TRACE_READ => read_trace(&shared, parse_params(params)?).await,
        methods::TRACE_GRAPH_GET => {
            let IdParams { id } = parse_params(params)?;
            shared.ask_memory(memory_contract::methods::TRACE_GRAPH, json!({"id": id})).await
        }
        other => Err(RpcError::unknown_method(other)),
    }
}

/// Who asked, from the `caller` the mesh stamps on a shared call: `cortexcode on Mac mini`.
fn caller_of(params: &Value) -> String {
    let caller = &params["caller"];
    match (caller["app"].as_str(), caller["name"].as_str()) {
        (Some(app), Some(name)) if !app.is_empty() && !name.is_empty() && !caller["local"].as_bool().unwrap_or(false) => format!("{app} on {name}"),
        (Some(app), _) if !app.is_empty() => app.to_owned(),
        _ => String::new(),
    }
}

/// A trace in the size asked for: one line, the summary, the chart's points, or raw records.
async fn read_trace(shared: &Arc<Shared>, p: TraceReadParams) -> Result<Value, RpcError> {
    if p.size == "records" {
        let params = json!({"id": p.id, "from": p.from.unwrap_or(0), "to": p.to.unwrap_or(u64::MAX >> 1), "kinds": p.kinds, "limit": p.limit});
        return shared.ask_memory(memory_contract::methods::TRACE_WINDOW, params).await;
    }
    let mut summary = shared.ask_memory(memory_contract::methods::TRACE_SUMMARY, json!({"id": p.id, "from": p.from, "to": p.to})).await?;
    match p.size.as_str() {
        "line" => Ok(json!({"line": trace_line(&summary)})),
        "series" => Ok(json!({"from": summary["from"], "to": summary["to"], "series": summary["series"]})),
        "" | "summary" => {
            if let Some(map) = summary.as_object_mut() {
                map.remove("series");
            }
            Ok(summary)
        }
        other => Err(RpcError::invalid_params(format!("size `{other}`: line, summary, series or records"))),
    }
}

/// `trace://t-…: 4m12s, exit 0; peak CPU 796%, 6.4 GB; ran rustc ×304, cargo` (about 120 characters).
fn trace_line(summary: &Value) -> String {
    let t = &summary["trace"];
    let mut parts = Vec::new();
    let span = summary["to"].as_u64().unwrap_or(0).saturating_sub(summary["from"].as_u64().unwrap_or(0));
    let mut head = util::duration_text(span);
    match (t["ended"].is_null(), t["exit_code"].as_i64()) {
        (true, _) => head.push_str(", running"),
        (false, Some(code)) => head.push_str(&format!(", exit {code}")),
        _ => {}
    }
    parts.push(head);
    let metric = |name: &str| summary["metrics"].as_array().and_then(|m| m.iter().find(|m| m["name"] == name)).and_then(|m| m["max"].as_f64());
    let mut peak = Vec::new();
    if let Some(cpu) = metric("cpu").filter(|v| *v > 0.0) {
        peak.push(format!("peak CPU {cpu:.0}%"));
    }
    if let Some(memory) = metric("memory").filter(|v| *v > 0.0) {
        peak.push(if memory >= 1e9 { format!("{:.1} GB", memory / 1e9) } else { format!("{:.0} MB", memory / 1e6) });
    }
    if !peak.is_empty() {
        parts.push(peak.join(", "));
    }
    let ran: Vec<String> = summary["processes"].as_array().into_iter().flatten().take(3)
        .filter_map(|p| { let n = p["name"].as_str()?; let c = p["count"].as_u64().unwrap_or(1); Some(if c > 1 { format!("{n} ×{c}") } else { n.to_owned() }) })
        .collect();
    if !ran.is_empty() {
        parts.push(format!("ran {}", ran.join(", ")));
    }
    if let Some(error) = summary["errors"].as_array().and_then(|e| e.first()).and_then(Value::as_str) {
        parts.push(error.chars().take(60).collect());
    }
    format!("trace://{}: {}", t["id"].as_str().unwrap_or(""), parts.join("; "))
}

struct SystemPlugin {
    shared: Arc<Shared>,
}

impl Plugin for SystemPlugin {
    fn handle(&self, ctx: Ctx, call: Call) -> BoxFuture<'static, Result<Value, RpcError>> {
        let _ = self.shared.ctx.set(ctx);
        start(&self.shared);
        let shared = self.shared.clone();
        Box::pin(async move { dispatch(shared, &call.method, call.params).await })
    }

    /// Sample the machine for real: memory and CPU are read, the process scan finds processes,
    /// the port scan runs, the data folder is writable.
    fn probe(&self, _ctx: Ctx) -> BoxFuture<'static, Result<ProbeReport, RpcError>> {
        let data_dir = self.shared.data_dir.clone();
        Box::pin(async move {
            let checks = tokio::task::spawn_blocking(move || {
                let mut checks = Vec::new();
                let timed = |name: &str, f: &mut dyn FnMut() -> Result<String, String>| {
                    let started = Instant::now();
                    let (ok, detail) = match f() {
                        Ok(detail) => (true, detail),
                        Err(detail) => (false, detail),
                    };
                    ProbeCheck { name: name.into(), ok, detail, ms: started.elapsed().as_millis() as u64 }
                };
                let mut sampler = Sampler::new();
                let (metrics, _) = sampler.tick(Power::default());
                checks.push(timed("metrics", &mut || {
                    if metrics.memory_total > 0 && !metrics.pressure.is_empty() {
                        Ok(format!("{} cores, {} GB, pressure {}", metrics.cores.len(), metrics.memory_total >> 30, metrics.pressure))
                    } else {
                        Err("no memory total".into())
                    }
                }));
                checks.push(timed("processes", &mut || {
                    let list = procs::list(&sampler.snapshot, &ProcessesParams { group: "app".into(), ..Default::default() });
                    if list.total > 0 {
                        Ok(format!("{} processes in {} apps", list.total, list.groups.len()))
                    } else {
                        Err("no processes".into())
                    }
                }));
                checks.push(timed("ports", &mut || Ok(format!("{} listening ports", sampler.ports.len()))));
                checks.push(timed("memory", &mut || {
                    if graph::ready() {
                        Ok(format!("graph loaded, {} writes waiting", graph::pending()))
                    } else {
                        Ok("waiting for memory: nothing is compared or kept until it answers".into())
                    }
                }));
                checks.push(timed("data", &mut || {
                    std::fs::create_dir_all(&data_dir)
                        .and_then(|_| std::fs::write(data_dir.join(".probe"), b"ok"))
                        .and_then(|_| std::fs::remove_file(data_dir.join(".probe")))
                        .map(|_| data_dir.display().to_string())
                        .map_err(|e| format!("{}: {e}", data_dir.display()))
                }));
                checks
            })
            .await
            .map_err(|e| RpcError::internal(e.to_string()))?;
            Ok(ProbeReport::from_checks(checks))
        })
    }

    fn activate(&self, ctx: Ctx) -> BoxFuture<'static, Result<(), RpcError>> {
        let _ = self.shared.ctx.set(ctx);
        start(&self.shared);
        Box::pin(async { Ok(()) })
    }

    /// A terminal's command started or finished: its trace begins or ends.
    fn event(&self, ctx: Ctx, topic: String, data: Value) -> BoxFuture<'static, ()> {
        let _ = self.shared.ctx.set(ctx);
        start(&self.shared);
        let shared = self.shared.clone();
        Box::pin(async move {
            if let Ok(run) = serde_json::from_value::<Run>(data) {
                shared.on_run(&topic, run).await;
            }
        })
    }
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_env("CORTEX_LOG").unwrap_or_else(|_| "warn".into()))
        .with_writer(std::io::stderr)
        .init();
    keys::import_files();
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("cc-system: cannot start the async runtime: {error}");
            std::process::exit(1);
        }
    };
    let code = runtime.block_on(async {
        let mut hello = Hello::new("cc-system", env!("CARGO_PKG_VERSION"), "system", "system@1");
        hello.provides = [
            methods::METRICS,
            methods::PROCESSES,
            methods::PROCESS,
            methods::SIGNAL,
            methods::PORTS,
            methods::ALERTS,
            methods::ALERT_ACT,
            methods::SWEEP,
            methods::SWEEP_RUN,
            methods::FINDING_IGNORE,
            methods::CHECK,
            methods::CVE,
            methods::ASK,
            methods::KEYS_SET,
            methods::KEYS_STATUS,
            methods::TIMELINE,
            methods::MEMORY_CHANGES,
            methods::SSH_HOSTS,
            methods::SSH_KEYS,
            methods::SHARES,
            methods::SCHEDULE_LIST,
            methods::SCHEDULE_GET,
            methods::SCHEDULE_CREATE,
            methods::SCHEDULE_EDIT,
            methods::SCHEDULE_DELETE,
            methods::SCHEDULE_RUN,
            methods::SCHEDULE_RUNS_LIST,
            methods::SCHEDULE_RUNS_READ,
            methods::TRACE_RUN,
            methods::TRACE_STOP,
            methods::TRACE_LIST,
            methods::TRACE_READ,
            methods::TRACE_GRAPH_GET,
            methods::TRACE_DELETE,
        ]
        .iter()
        .map(|m| (*m).to_owned())
        .collect();
        // Reading the machine is fine from a shell; acting on it (signals, alerts, sweeps, schedules)
        // is not.
        hello.commands = [
            methods::METRICS,
            methods::PROCESSES,
            methods::PROCESS,
            methods::PORTS,
            methods::ALERTS,
            methods::SWEEP,
            methods::MEMORY_CHANGES,
            methods::SSH_HOSTS,
            methods::SSH_KEYS,
            methods::SCHEDULE_LIST,
            methods::SCHEDULE_GET,
            methods::SCHEDULE_RUNS_LIST,
            methods::SCHEDULE_RUNS_READ,
            methods::TRACE_LIST,
            methods::TRACE_READ,
            methods::TRACE_GRAPH_GET,
        ]
            .iter()
            .map(|m| (*m).to_owned())
            .collect();
        hello.subscribes = vec![terminal_contract::topics::RUN_STARTED.into(), terminal_contract::topics::RUN_FINISHED.into()];
        let plugin = Arc::new(SystemPlugin { shared: Arc::new(Shared::new()) });
        let mut terminate = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(stream) => stream,
            Err(error) => {
                eprintln!("cc-system: cannot handle SIGTERM: {error}");
                return 1;
            }
        };
        let outcome = tokio::select! {
            outcome = cc_protocol::run_plugin(hello, plugin) => outcome,
            _ = terminate.recv() => Ok(()),
            _ = tokio::signal::ctrl_c() => Ok(()),
        };
        match outcome {
            Ok(()) => 0,
            Err(error) => {
                eprintln!("cc-system: {error}");
                2
            }
        }
    });
    std::process::exit(code);
}

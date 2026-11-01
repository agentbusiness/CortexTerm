//! Cleanup (`cleanup@1`, protocol/src/contracts/cleanup.rs): disk space this computer can get
//! back, found by recipes and checks, decided by the person (or planned by the local model within
//! the plugin's rules), and kept in the terminal's graph. See plugins/cleanup/README.md.

mod ai;
mod clean;
mod dupes;
mod git;
mod graph;
mod inuse;
mod recipes;
mod scan;
mod stale;
mod state;
mod walk;

use cc_protocol::contracts::cleanup::{
    Applied, ApplyParams, Decision, ExplainParams, Explained, Item, Outcome, PlanParams, ScanInfo, ScanParams, events, methods,
};
use cc_protocol::contracts::lifecycle::{Hello, ProbeCheck, ProbeReport};
use cc_protocol::{BoxFuture, Call, Ctx, Plugin, RpcError, parse_params, run_plugin, to_value};
use serde_json::{Value, json};
use state::{State, lock};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const DAY_MS: u64 = 86_400_000;
/// "Not now" brings an item back after this.
const LATER_DAYS: u64 = 30;
/// Items written to the graph per batch.
const PER_BATCH: usize = 150;

struct Cleanup {
    home: PathBuf,
    state: State,
    /// The running scan's counters (its stop flag among them).
    live: Mutex<Option<Arc<scan::Live>>>,
    started: std::sync::atomic::AtomicBool,
}

impl Cleanup {
    fn report(&self) -> Result<Value, RpcError> {
        to_value(&self.state.report(&self.home))
    }

    /// Kept items, and postponed ones not yet due: their folders are not read.
    fn skipped(&self) -> (HashSet<PathBuf>, HashSet<String>) {
        let now = cc_protocol::contracts::now_ms();
        let mut paths = HashSet::new();
        let mut ids = HashSet::new();
        for item in lock(&self.state.items).values() {
            let holds = item.decision.as_ref().is_some_and(|d| d.verdict == "keep" || (d.verdict == "later" && d.until_ms > now));
            if holds {
                ids.insert(item.id.clone());
                if !item.id.starts_with("dupe:") {
                    paths.insert(PathBuf::from(&item.path));
                }
            }
        }
        (paths, ids)
    }
}

async fn scan_job(this: Arc<Cleanup>, ctx: Ctx) {
    let id = uuid::Uuid::new_v4().simple().to_string();
    let started = cc_protocol::contracts::now_ms();
    *lock(&this.state.scan) = Some(ScanInfo { id: id.clone(), started_ms: started, ..Default::default() });
    let (skip, skip_ids) = this.skipped();
    // When CortexTerm last ran a command in each folder: a project used lately keeps its build.
    let since = started.saturating_sub(30 * DAY_MS);
    let runs: HashMap<String, u64> = graph::query(
        "MATCH (c:CommandRun)-[:IN]->(f:Folder) WHERE c.started_ms > $since RETURN f.key, max(c.started_ms)",
        json!({ "since": since }),
        5000,
    )
    .await
    .unwrap_or_default()
    .into_iter()
    .filter_map(|row| Some((row.first()?.as_str()?.to_owned(), row.get(1)?.as_f64()? as u64)))
    .collect();
    let live = Arc::new(scan::Live::default());
    *lock(&this.live) = Some(live.clone());
    let ticker = {
        let (live, ctx, id) = (live.clone(), ctx.clone(), id.clone());
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                ctx.publish(events::PROGRESS, serde_json::to_value(live.progress(&id)).unwrap_or(Value::Null));
            }
        })
    };
    let input = scan::Input { home: this.home.clone(), skip: skip.clone(), skip_ids, runs };
    let work = live.clone();
    let result = tokio::task::spawn_blocking(move || scan::run(input, &work)).await.unwrap_or_else(|e| Err(e.to_string()));
    ticker.abort();
    *lock(&this.live) = None;
    let finished = cc_protocol::contracts::now_ms();
    match result {
        Ok(output) => {
            let info = ScanInfo {
                id: id.clone(),
                started_ms: started,
                finished_ms: finished,
                files: output.files,
                bytes: output.bytes,
                stopped: output.stopped,
                skipped_kept: skip.len() as u32,
            };
            let found_bytes: u64 = output.items.iter().map(|i| i.bytes).sum();
            let mut gone = Vec::new();
            {
                let mut items = lock(&this.state.items);
                let previous = std::mem::take(&mut *items);
                let fresh: HashSet<String> = output.items.iter().map(|i| i.id.clone()).collect();
                for (key, old) in previous {
                    let holds = old.decision.as_ref().is_some_and(|d| d.verdict == "keep" || (d.verdict == "later" && d.until_ms > finished));
                    if holds && !fresh.contains(&key) {
                        items.insert(key, old);
                    } else if !fresh.contains(&key) && !output.stopped {
                        gone.push(graph::r("Reclaimable", key));
                    }
                }
                for item in output.items {
                    items.insert(item.id.clone(), item);
                }
            }
            *lock(&this.state.scan) = Some(info.clone());
            // The scan hangs from this machine and its finds from the scan: without the machine's
            // root node memory would refuse new finds, so they stay in RAM until a later scan.
            match graph::machine_now().await {
                Some(machine) => {
                    let mut batch = graph::Batch::default();
                    let scan_ref = batch.node(
                        "CleanupScan",
                        id.clone(),
                        json!({ "started_ms": started, "finished_ms": finished, "files": info.files, "bytes": info.bytes, "found_bytes": found_bytes, "stopped": info.stopped, "skipped_kept": info.skipped_kept }),
                        json!({}),
                    );
                    batch.edge(&scan_ref, "ON", &machine, json!({}));
                    graph::put(batch);
                    let items: Vec<Item> = lock(&this.state.items).values().cloned().collect();
                    for chunk in items.chunks(PER_BATCH) {
                        let mut batch = graph::Batch::default();
                        for item in chunk {
                            state::record(&mut batch, item, Some(&scan_ref));
                        }
                        graph::put(batch);
                    }
                }
                None => tracing::warn!("memory has not named this machine's root node yet: the scan's finds are kept in RAM only"),
            }
            graph::retire(gone, "gone");
        }
        Err(error) => {
            tracing::warn!("scan failed: {error}");
            *lock(&this.state.scan) = Some(ScanInfo { id, started_ms: started, finished_ms: finished, stopped: true, ..Default::default() });
        }
    }
    this.state.running.store(false, Ordering::SeqCst);
    ctx.publish(events::CHANGED, json!({}));
}

async fn apply(this: Arc<Cleanup>, ctx: Ctx, params: ApplyParams) -> Result<Applied, RpcError> {
    let by = if params.by == "ai" { "ai" } else { "user" };
    let now = cc_protocol::contracts::now_ms();
    let mut applied = Applied::default();
    let mut cleaning = Vec::new();
    let mut batch = graph::Batch::default();
    for step in &params.steps {
        let Some(mut item) = lock(&this.state.items).get(&step.id).cloned() else {
            applied.outcomes.push(Outcome { id: step.id.clone(), ok: false, freed: 0, detail: "not found; scan again".into() });
            continue;
        };
        match step.action.as_str() {
            "clean" => {
                if by == "ai" && !ai::may_clean(&item) {
                    applied.outcomes.push(Outcome { id: item.id, ok: false, freed: 0, detail: "the AI may clean only regenerable, idle items".into() });
                    continue;
                }
                cleaning.push((item, step.reason.clone()));
            }
            "keep" | "later" | "reset" => {
                let decision = Decision {
                    verdict: step.action.clone(),
                    by: by.into(),
                    reason: step.reason.clone(),
                    at_ms: now,
                    until_ms: if step.action == "later" { now + LATER_DAYS * DAY_MS } else { 0 },
                };
                item.state = match step.action.as_str() {
                    "keep" => "kept",
                    "later" => "later",
                    _ => "open",
                }
                .into();
                state::record_decision(&mut batch, &item, &decision);
                item.decision = (step.action != "reset").then_some(decision);
                state::record(&mut batch, &item, None);
                lock(&this.state.items).insert(item.id.clone(), item.clone());
                applied.outcomes.push(Outcome { id: item.id, ok: true, freed: 0, detail: String::new() });
            }
            other => applied.outcomes.push(Outcome { id: item.id, ok: false, freed: 0, detail: format!("unknown action {other}") }),
        }
    }
    graph::put(batch);
    if !cleaning.is_empty() {
        let home = this.home.clone();
        let done = tokio::task::spawn_blocking(move || {
            // Who uses what, read once just before.
            let snapshot = inuse::Snapshot::take();
            cleaning.into_iter().map(|(item, reason)| { let result = clean::clean(&item, &home, &snapshot); (item, reason, result) }).collect::<Vec<_>>()
        })
        .await
        .map_err(|e| RpcError::internal(e.to_string()))?;
        for (mut item, reason, result) in done {
            let at = cc_protocol::contracts::now_ms();
            let action_id = uuid::Uuid::new_v4().simple().to_string();
            let (ok, freed, detail) = match result {
                Ok(done) => (true, done.freed, String::new()),
                Err(why) => (false, 0, why),
            };
            let mut batch = graph::Batch::default();
            let decision = Decision { verdict: "clean".into(), by: by.into(), reason: reason.clone(), at_ms: at, until_ms: 0 };
            state::record_decision(&mut batch, &item, &decision);
            if ok {
                item.state = "cleaned".into();
                this.state.freed.fetch_add(freed, Ordering::SeqCst);
                lock(&this.state.items).remove(&item.id);
            } else {
                item.decision = Some(decision);
                lock(&this.state.items).insert(item.id.clone(), item.clone());
            }
            state::record(&mut batch, &item, None);
            let action = batch.node(
                "CleanupAction",
                action_id,
                json!({ "at_ms": at, "by": by, "how": item.how, "freed": freed, "ok": ok, "detail": detail, "reason": reason }),
                json!({}),
            );
            batch.edge(&action, "CLEANED", &graph::r("Reclaimable", item.id.clone()), json!({}));
            if let Some(machine) = graph::machine_now().await {
                batch.edge(&action, "ON", &machine, json!({}));
            }
            graph::put(batch);
            graph::append("cleanup.actions", vec![json!({ "at": at, "id": item.id, "path": item.path, "by": by, "how": item.how, "freed": freed, "ok": ok })]);
            if ok {
                graph::retire(vec![graph::r("Reclaimable", item.id.clone())], "cleaned");
            }
            applied.freed += freed;
            applied.outcomes.push(Outcome { id: item.id, ok, freed, detail });
        }
    }
    ctx.publish(events::CHANGED, json!({}));
    Ok(applied)
}

/// The person's latest decisions, as lines the model reads ("kept: Agent transcripts ~/.claude/…").
async fn history(home: &std::path::Path) -> Vec<String> {
    graph::query(
        "MATCH (d:CleanupDecision) WHERE d.by = 'user' RETURN d.verdict, d.kind, d.path, d.reason ORDER BY d.at_ms DESC LIMIT 25",
        json!({}),
        25,
    )
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|row| {
        let text = |i: usize| row.get(i).and_then(Value::as_str).unwrap_or_default().to_owned();
        let verdict = match text(0).as_str() {
            "keep" => "kept",
            "later" => "postponed",
            "clean" => "cleaned",
            _ => "reconsidered",
        };
        let reason = text(3);
        format!("{verdict}: {} {}{}", text(1), ai::short(&text(2), home), if reason.is_empty() { String::new() } else { format!(" ({reason})") })
    })
    .collect()
}

struct Server(Arc<Cleanup>);

impl Plugin for Server {
    fn handle(&self, ctx: Ctx, call: Call) -> BoxFuture<'static, Result<Value, RpcError>> {
        let this = self.0.clone();
        Box::pin(async move {
            match call.method.as_str() {
                methods::STATUS => this.report(),
                methods::SCAN => {
                    let _: ScanParams = parse_params(call.params).unwrap_or_default();
                    if !this.state.running.swap(true, Ordering::SeqCst) {
                        tokio::spawn(scan_job(this.clone(), ctx));
                    }
                    this.report()
                }
                methods::STOP => {
                    if let Some(live) = lock(&this.live).as_ref() {
                        live.counters.stop.store(true, Ordering::SeqCst);
                    }
                    this.report()
                }
                methods::APPLY => to_value(&apply(this, ctx, parse_params(call.params)?).await?),
                methods::EXPLAIN => {
                    let p: ExplainParams = parse_params(call.params)?;
                    let item = lock(&this.state.items).get(&p.id).cloned().ok_or_else(|| RpcError::new("not_found", "scan again"))?;
                    let text = ai::explain(&ctx, &item, &this.home).await.map_err(|e| RpcError::new("unavailable", e))?;
                    to_value(&Explained { text })
                }
                methods::PLAN => {
                    let p: PlanParams = parse_params(call.params)?;
                    let items: Vec<Item> = lock(&this.state.items)
                        .values()
                        .filter(|i| matches!(i.state.as_str(), "open" | "warm" | "in_use") && (p.ids.is_empty() || p.ids.contains(&i.id)))
                        .cloned()
                        .collect();
                    let history = history(&this.home).await;
                    let plan = ai::plan(&ctx, items, history, &this.home).await.map_err(|e| RpcError::new("unavailable", e))?;
                    to_value(&plan)
                }
                other => Err(RpcError::unknown_method(other)),
            }
        })
    }

    fn probe(&self, _ctx: Ctx) -> BoxFuture<'static, Result<ProbeReport, RpcError>> {
        let recipes = recipes::load();
        Box::pin(async move {
            Ok(ProbeReport::from_checks(vec![ProbeCheck {
                name: "recipes".into(),
                ok: recipes.is_ok(),
                detail: match recipes {
                    Ok(list) => format!("{} recipes", list.len()),
                    Err(error) => error,
                },
                ms: 0,
            }]))
        })
    }

    /// The frame made this instance active: start writing to the graph and load what it holds.
    fn activate(&self, ctx: Ctx) -> BoxFuture<'static, Result<(), RpcError>> {
        let this = self.0.clone();
        if !this.started.swap(true, Ordering::SeqCst) {
            tokio::spawn(async move {
                graph::start(ctx).await;
                this.state.load().await;
            });
        }
        Box::pin(async { Ok(()) })
    }

    fn shutdown(&self, _ctx: Ctx) -> BoxFuture<'static, ()> {
        if let Some(live) = lock(&self.0.live).as_ref() {
            live.counters.stop.store(true, Ordering::SeqCst);
        }
        Box::pin(async {})
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().with_writer(std::io::stderr).init();
    let Some(home) = std::env::var_os("HOME").map(PathBuf::from) else {
        eprintln!("cc-cleanup: the serving user has no home folder");
        std::process::exit(1);
    };
    // The walk runs at utility priority: it gives way to everything the person does.
    let threads = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4).clamp(2, 8);
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(threads)
        .start_handler(|_| {
            #[cfg(target_os = "macos")]
            unsafe {
                libc::pthread_set_qos_class_self_np(libc::qos_class_t::QOS_CLASS_UTILITY, 0);
            }
        })
        .build_global();
    let this = Arc::new(Cleanup { home, state: State::default(), live: Mutex::new(None), started: Default::default() });
    let mut hello = Hello::new("cc-cleanup", env!("CARGO_PKG_VERSION"), "cleanup", "cleanup@1");
    hello.provides = methods::ALL.iter().map(|m| (*m).to_owned()).collect();
    let server = Arc::new(Server(this));
    if let Err(error) = run_plugin(hello, server).await {
        eprintln!("cc-cleanup: {error}");
        std::process::exit(1);
    }
}

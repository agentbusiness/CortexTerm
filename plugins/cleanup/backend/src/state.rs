//! The plugin's working copy of what the graph holds: the open finds, their decisions, the last
//! scan and the space freed so far. Loaded from the graph at start; every change is written back.

use crate::graph::{self, Batch};
use cc_protocol::contracts::cleanup::{Decision, Disk, Item, Report, ScanInfo};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[derive(Default)]
pub struct State {
    pub items: Mutex<BTreeMap<String, Item>>,
    pub scan: Mutex<Option<ScanInfo>>,
    pub running: AtomicBool,
    pub freed: AtomicU64,
}

pub fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|e| e.into_inner())
}

fn text(map: &Map<String, Value>, name: &str) -> String {
    map.get(name).and_then(Value::as_str).unwrap_or_default().to_owned()
}

fn number(map: &Map<String, Value>, name: &str) -> u64 {
    map.get(name).and_then(Value::as_f64).unwrap_or(0.0).max(0.0) as u64
}

fn texts(map: &Map<String, Value>, name: &str) -> Vec<String> {
    map.get(name).and_then(Value::as_array).map(|list| list.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default()
}

impl State {
    /// What the graph holds, read once memory answers.
    pub async fn load(&self) {
        let mut items = BTreeMap::new();
        if let Ok(rows) = graph::query("MATCH (r:Reclaimable) WHERE r.ended_ms IS NULL RETURN r", json!({}), 5000).await {
            for row in rows {
                let p = graph::props(&row[0]);
                let item = Item {
                    id: text(p, "key"),
                    path: text(p, "path"),
                    title: text(p, "title"),
                    kind: text(p, "kind"),
                    recipe: text(p, "recipe"),
                    bytes: number(p, "bytes"),
                    files: number(p, "files"),
                    newest_ms: number(p, "newest_ms"),
                    project: text(p, "project"),
                    scope: text(p, "scope"),
                    safety: text(p, "safety"),
                    state: text(p, "status"),
                    in_use_by: texts(p, "in_use_by"),
                    why: text(p, "why"),
                    regenerate: text(p, "regenerate"),
                    how: text(p, "how"),
                    copies: texts(p, "copies"),
                    decision: None,
                };
                if !item.id.is_empty() {
                    items.insert(item.id.clone(), item);
                }
            }
        }
        if let Ok(rows) = graph::query("MATCH (d:CleanupDecision)-[:ABOUT]->(r:Reclaimable) WHERE r.ended_ms IS NULL RETURN d", json!({}), 5000).await {
            for row in rows {
                let p = graph::props(&row[0]);
                if let Some(item) = items.get_mut(&text(p, "key")) {
                    item.decision = Some(Decision {
                        verdict: text(p, "verdict"),
                        by: text(p, "by"),
                        reason: text(p, "reason"),
                        at_ms: number(p, "at_ms"),
                        until_ms: number(p, "until_ms"),
                    });
                }
            }
        }
        if let Ok(rows) = graph::query("MATCH (s:CleanupScan) RETURN s ORDER BY s.started_ms DESC LIMIT 1", json!({}), 1).await
            && let Some(row) = rows.first()
        {
            let p = graph::props(&row[0]);
            *lock(&self.scan) = Some(ScanInfo {
                id: text(p, "key"),
                started_ms: number(p, "started_ms"),
                finished_ms: number(p, "finished_ms"),
                files: number(p, "files"),
                bytes: number(p, "bytes"),
                stopped: p.get("stopped").and_then(Value::as_bool).unwrap_or(false),
                skipped_kept: number(p, "skipped_kept") as u32,
            });
        }
        if let Ok(rows) = graph::query("MATCH (a:CleanupAction) WHERE a.ok = true RETURN sum(a.freed)", json!({}), 1).await
            && let Some(freed) = rows.first().and_then(|row| row.first()).and_then(Value::as_f64)
        {
            self.freed.store(freed.max(0.0) as u64, Ordering::SeqCst);
        }
        let mut current = lock(&self.items);
        // A scan that finished before memory answered wins.
        if current.is_empty() {
            *current = items;
        }
    }

    pub fn report(&self, home: &std::path::Path) -> Report {
        let now = cc_protocol::contracts::now_ms();
        let mut items: Vec<Item> = lock(&self.items).values().cloned().collect();
        // A postponement that ran out shows the item again.
        for item in &mut items {
            if item.state == "later" && item.decision.as_ref().is_some_and(|d| d.until_ms <= now) {
                item.state = "open".into();
            }
        }
        items.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        Report {
            disk: disk(home),
            scan: lock(&self.scan).clone(),
            running: self.running.load(Ordering::SeqCst),
            items,
            freed_bytes: self.freed.load(Ordering::SeqCst),
        }
    }
}

pub fn disk(path: &std::path::Path) -> Disk {
    use std::os::unix::ffi::OsStrExt;
    let Ok(name) = std::ffi::CString::new(path.as_os_str().as_bytes()) else { return Disk::default() };
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: a NUL-terminated path and a zeroed struct the call fills.
    if unsafe { libc::statvfs(name.as_ptr(), &mut stat) } != 0 {
        return Disk::default();
    }
    let unit = stat.f_frsize;
    Disk { total: stat.f_blocks as u64 * unit, free: stat.f_bavail as u64 * unit }
}

/// One find as a node with its edges.
pub fn record(batch: &mut Batch, item: &Item, scan: Option<&graph::GraphRef>) {
    let node = batch.node(
        "Reclaimable",
        item.id.clone(),
        json!({
            "path": item.path, "title": item.title, "kind": item.kind, "recipe": item.recipe, "scope": item.scope,
            "safety": item.safety, "how": item.how, "why": item.why, "regenerate": item.regenerate, "project": item.project,
            "copies": item.copies, "in_use_by": item.in_use_by, "files": item.files, "newest_ms": item.newest_ms,
        }),
        json!({ "bytes": item.bytes, "status": item.state }),
    );
    let recipe = batch.node("CleanupRecipe", item.recipe.clone(), json!({ "title": item.title, "kind": item.kind, "safety": item.safety }), json!({}));
    batch.edge(&node, "MATCHES", &recipe, json!({}));
    let path = std::path::Path::new(&item.path);
    if let Some(parent) = path.parent() {
        let folder = batch.node("Folder", parent.to_string_lossy(), json!({}), json!({}));
        batch.edge(&node, "IN", &folder, json!({}));
    }
    if !item.project.is_empty() {
        let project = batch.node("Folder", item.project.clone(), json!({}), json!({}));
        batch.edge(&node, "OF_PROJECT", &project, json!({}));
    }
    if let Some(scan) = scan {
        batch.edge(&node, "FOUND_BY", scan, json!({}));
    }
    for why in &item.in_use_by {
        let program = why.split(" (pid").next().unwrap_or(why);
        if why.contains("(pid") || why.ends_with(" is open") {
            let program = batch.node("Program", program.trim_end_matches(" is open").to_owned(), json!({}), json!({}));
            batch.edge(&node, "USED_BY", &program, json!({ "why": why }));
        }
    }
    for copy in &item.copies {
        let file = batch.node("LargeFile", copy.clone(), json!({}), json!({}));
        batch.edge(&file, "COPY_IN", &node, json!({}));
    }
}

/// A decision as a node about its find.
pub fn record_decision(batch: &mut Batch, item: &Item, decision: &Decision) {
    let about = graph::r("Reclaimable", item.id.clone());
    let node = batch.node(
        "CleanupDecision",
        item.id.clone(),
        json!({ "by": decision.by, "reason": decision.reason, "at_ms": decision.at_ms, "until_ms": decision.until_ms, "path": item.path, "kind": item.kind, "recipe": item.recipe }),
        json!({ "verdict": decision.verdict }),
    );
    batch.edge(&node, "ABOUT", &about, json!({}));
}

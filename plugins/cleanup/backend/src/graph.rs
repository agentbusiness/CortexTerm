//! What this plugin keeps lives in the terminal's graph (docs/GRAPH-MODEL.md, "Disk cleanup"):
//!
//! ```text
//! (:CleanupScan {key, started_ms, finished_ms, files, bytes, found_bytes})-[:ON]->(:Machine)
//! (:Reclaimable {key: path | dupe:<hash>, path, title, kind, recipe, scope, safety, how, why,
//!                regenerate, project, copies, in_use_by, files, newest_ms, bytes*, status*})
//!     -[:FOUND_BY]->(:CleanupScan)   -[:MATCHES]->(:CleanupRecipe {key: id, title, kind, safety})
//!     -[:IN]->(:Folder {key: its folder})   -[:OF_PROJECT]->(:Folder {key: project root})
//!     -[:USED_BY {why}]->(:Program {key: name})          while a program uses it
//! (:LargeFile {key: path})-[:COPY_IN]->(:Reclaimable)    each copy of a duplicate set
//! (:CleanupDecision {key: item key, verdict, by, reason, at_ms, until_ms})-[:ABOUT]->(:Reclaimable)
//! (:CleanupAction {key, at_ms, by, how, freed, ok, detail})-[:CLEANED]->(:Reclaimable)  -[:ON]->(:Machine)
//! stream `cleanup.actions`   {at, id, path, by, how, freed, ok}
//! ```
//!
//! A find not seen again is retired (`gone`); a cleaned one is retired as `cleaned`. Writes are
//! sent in order; while memory is away they wait in RAM, and a refused batch is logged and dropped.

use cc_protocol::Ctx;
pub use cc_protocol::contracts::memory::GraphRef;
use cc_protocol::contracts::memory::{GraphEdge, GraphNode, GraphPutParams, GraphRetireParams, StreamAppendParams, methods};
use serde_json::{Map, Value, json};
use std::sync::OnceLock;
use std::time::Duration;
use tokio::sync::mpsc;

static CTX: OnceLock<Ctx> = OnceLock::new();
static MACHINE: OnceLock<String> = OnceLock::new();
static OUTBOX: OnceLock<mpsc::UnboundedSender<(&'static str, Value)>> = OnceLock::new();

pub fn r(label: &str, key: impl Into<String>) -> GraphRef {
    GraphRef { label: label.to_owned(), key: key.into() }
}

pub fn machine() -> Option<GraphRef> {
    MACHINE.get().map(|key| r("Machine", key.clone()))
}

/// This machine's root node, asked of memory once more when [`start`] did not learn it (memory
/// was away that minute). None while memory still does not name it.
pub async fn machine_now() -> Option<GraphRef> {
    if MACHINE.get().is_none() {
        let ctx = CTX.get()?;
        if let Ok(Ok(value)) = tokio::time::timeout(Duration::from_secs(10), ctx.call(methods::GRAPH_MACHINE, json!({}))).await
            && let Some(key) = value.get("key").and_then(Value::as_str).filter(|key| !key.is_empty())
        {
            let _ = MACHINE.set(key.to_owned());
        }
    }
    machine()
}

#[derive(Default)]
pub struct Batch {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl Batch {
    pub fn node(&mut self, label: &str, key: impl Into<String>, props: Value, temporal: Value) -> GraphRef {
        let key = key.into();
        self.nodes.push(GraphNode { label: label.into(), key: key.clone(), props: object(props), temporal: object(temporal) });
        r(label, key)
    }

    pub fn edge(&mut self, from: &GraphRef, rel: &str, to: &GraphRef, props: Value) {
        self.edges.push(GraphEdge { from: from.clone(), rel: rel.into(), to: to.clone(), props: object(props), temporal: Map::new() });
    }
}

/// Properties without nulls for absent texts: an empty string or list is left out.
fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map
            .into_iter()
            .filter(|(_, v)| !matches!(v, Value::String(s) if s.is_empty()) && !matches!(v, Value::Array(a) if a.is_empty()))
            .collect(),
        _ => Map::new(),
    }
}

/// Sent in order. A batch is nodes with the edges that connect them, under memory's limit of
/// 5000 together: callers write a few hundred finds per batch.
pub fn put(batch: Batch) {
    if batch.nodes.is_empty() && batch.edges.is_empty() {
        return;
    }
    if let Some(outbox) = OUTBOX.get() {
        let params = GraphPutParams { nodes: batch.nodes, edges: batch.edges, ..Default::default() };
        let _ = outbox.send((methods::GRAPH_PUT, serde_json::to_value(params).unwrap_or(Value::Null)));
    }
}

pub fn retire(refs: Vec<GraphRef>, reason: &str) {
    if refs.is_empty() {
        return;
    }
    if let Some(outbox) = OUTBOX.get() {
        let params = GraphRetireParams { refs, reason: Some(reason.into()), at_ms: None };
        let _ = outbox.send((methods::GRAPH_RETIRE, serde_json::to_value(params).unwrap_or(Value::Null)));
    }
}

pub fn append(topic: &str, records: Vec<Value>) {
    if let Some(outbox) = OUTBOX.get() {
        let params = StreamAppendParams { topic: topic.into(), records, retention_days: Some(365) };
        let _ = outbox.send((methods::STREAM_APPEND, serde_json::to_value(params).unwrap_or(Value::Null)));
    }
}

/// Start the writer and learn this machine's root node. Returns once memory answered (or gave up
/// after a minute: reads then come back empty and writes wait).
pub async fn start(ctx: Ctx) {
    let _ = CTX.set(ctx.clone());
    let (send, mut receive) = mpsc::unbounded_channel::<(&'static str, Value)>();
    let _ = OUTBOX.set(send);
    for _ in 0..60 {
        if let Ok(Ok(value)) = tokio::time::timeout(Duration::from_secs(10), ctx.call(methods::GRAPH_MACHINE, json!({}))).await
            && let Some(key) = value.get("key").and_then(Value::as_str)
        {
            let _ = MACHINE.set(key.to_owned());
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    tokio::spawn(async move {
        while let Some((method, params)) = receive.recv().await {
            loop {
                match tokio::time::timeout(Duration::from_secs(30), ctx.call(method, params.clone())).await {
                    Ok(Ok(_)) => break,
                    Ok(Err(error)) if error.code == "invalid_params" => {
                        tracing::warn!("memory refused a {method}: {}", error.message);
                        break;
                    }
                    _ => tokio::time::sleep(Duration::from_secs(2)).await,
                }
            }
        }
    });
}

/// One read-only Cypher statement; rows of plain JSON.
pub async fn query(cypher: &str, params: Value, limit: u32) -> Result<Vec<Vec<Value>>, String> {
    let ctx = CTX.get().ok_or("not started")?;
    let params = json!({ "cypher": cypher, "params": params, "limit": limit });
    let value = tokio::time::timeout(Duration::from_secs(20), ctx.call(methods::GRAPH_QUERY, params))
        .await
        .map_err(|_| "memory did not answer".to_owned())?
        .map_err(|e| e.message)?;
    Ok(value.get("rows").and_then(Value::as_array).map(|rows| rows.iter().filter_map(|row| row.as_array().cloned()).collect()).unwrap_or_default())
}

/// A returned node's properties.
pub fn props(node: &Value) -> &Map<String, Value> {
    static EMPTY: OnceLock<Map<String, Value>> = OnceLock::new();
    node.get("properties").and_then(Value::as_object).unwrap_or_else(|| EMPTY.get_or_init(Map::new))
}

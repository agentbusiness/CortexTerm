//! Everything this plugin keeps lives in the terminal's graph, served by the memory plugin
//! (`memory@1`, docs/GRAPH-MODEL.md): nodes and edges, temporal properties for values that
//! change, streams for histories. Nothing is written to files.
//!
//! Writes go through one ordered outbox in RAM: [`put`], [`retire`] and [`append`] return at once,
//! and a writer sends the calls in order. While memory is not reachable (starting, restarting,
//! busy) the writes wait in RAM and are sent again; a write memory refuses (a bad batch) is logged
//! and dropped, so it never blocks the ones after it. Reads ([`query`], [`stream_read`]) ask
//! memory directly.
//!
//! The plugin starts before memory may answer: [`ready`] turns true once this Mac's root node is
//! known, the old files are moved in (`migrate`) and every module has loaded what it keeps. Until
//! then nothing compares against a baseline and nothing is written.

use cc_protocol::Ctx;
use cc_protocol::contracts::memory::{
    GraphEdge, GraphLayer, GraphNode, GraphPutParams, GraphRef, GraphRetireParams, StreamAppendParams, StreamEntry, StreamReadResult, methods,
};
use serde_json::{Map, Value, json};
use std::collections::{HashSet, VecDeque};
use std::future::Future;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// Nodes and edges per put (memory's limit).
const MAX_ITEMS: usize = 5000;
/// Writes held while memory is away; the oldest go first when there are more.
const BACKLOG: usize = 4000;
/// A call memory does not answer within this is tried again.
const CALL_LIMIT: Duration = Duration::from_secs(30);
/// Rows per page of a long read.
const PAGE: u64 = 5000;

static CTX: OnceLock<Ctx> = OnceLock::new();
/// This Mac's root node's key (`memory.graph.machine`).
static MACHINE: OnceLock<String> = OnceLock::new();
static READY: AtomicBool = AtomicBool::new(false);
static OUTBOX: Mutex<VecDeque<Op>> = Mutex::new(VecDeque::new());
/// A write is being sent (it leaves the outbox only once memory took it).
static SENDING: AtomicBool = AtomicBool::new(false);
/// Writes memory refused (and that were dropped).
static REFUSED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static DROPPED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
static WAKE: tokio::sync::Notify = tokio::sync::Notify::const_new();
static READY_SIGNAL: tokio::sync::Notify = tokio::sync::Notify::const_new();

enum Op {
    Put(GraphPutParams),
    Retire(GraphRetireParams),
    Append(StreamAppendParams),
}

impl Op {
    fn call(&self) -> (&'static str, Value) {
        match self {
            Op::Put(p) => (methods::GRAPH_PUT, serde_json::to_value(p).unwrap_or(Value::Null)),
            Op::Retire(p) => (methods::GRAPH_RETIRE, serde_json::to_value(p).unwrap_or(Value::Null)),
            Op::Append(p) => (methods::STREAM_APPEND, serde_json::to_value(p).unwrap_or(Value::Null)),
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------------------------
// Building batches

/// A node by identity.
pub fn r(label: &str, key: impl Into<String>) -> GraphRef {
    GraphRef { label: label.to_owned(), key: key.into() }
}

/// This Mac's root node (known once memory answered).
pub fn machine() -> Option<GraphRef> {
    MACHINE.get().map(|key| r("Machine", key.clone()))
}

/// Properties set on a node or an edge, chained: `.p("name", "Slack").t("version", "4.41")`.
pub trait Props {
    fn props(&mut self) -> &mut Map<String, Value>;
    fn temporal(&mut self) -> &mut Map<String, Value>;

    /// An ordinary property (`null` removes it).
    fn p(&mut self, name: &str, value: impl Into<Value>) -> &mut Self {
        self.props().insert(name.to_owned(), value.into());
        self
    }

    /// A property only when there is a value; nothing is written otherwise.
    fn po<V: Into<Value>>(&mut self, name: &str, value: Option<V>) -> &mut Self {
        if let Some(value) = value {
            self.props().insert(name.to_owned(), value.into());
        }
        self
    }

    /// A non-empty text only.
    fn ps(&mut self, name: &str, value: &str) -> &mut Self {
        if !value.is_empty() {
            self.props().insert(name.to_owned(), Value::String(value.to_owned()));
        }
        self
    }

    /// A list of text (an empty one removes the property: an empty list has no type).
    fn pl(&mut self, name: &str, list: Vec<String>) -> &mut Self {
        let value = if list.is_empty() { Value::Null } else { Value::from(list) };
        self.props().insert(name.to_owned(), value);
        self
    }

    /// A temporal property: its history keeps every change.
    fn t(&mut self, name: &str, value: impl Into<Value>) -> &mut Self {
        self.temporal().insert(name.to_owned(), value.into());
        self
    }
}

impl Props for GraphNode {
    fn props(&mut self) -> &mut Map<String, Value> {
        &mut self.props
    }
    fn temporal(&mut self) -> &mut Map<String, Value> {
        &mut self.temporal
    }
}

impl Props for GraphEdge {
    fn props(&mut self) -> &mut Map<String, Value> {
        &mut self.props
    }
    fn temporal(&mut self) -> &mut Map<String, Value> {
        &mut self.temporal
    }
}

/// Nodes with the edges that connect them, written together: a put is split only between units,
/// so every node arrives with its edges. Units are written in order, parents first.
#[derive(Default, Debug, Clone)]
pub struct Unit {
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

impl Unit {
    pub fn node(&mut self, label: &str, key: impl Into<String>) -> &mut GraphNode {
        self.nodes.push(GraphNode { label: label.to_owned(), key: key.into(), ..Default::default() });
        self.nodes.last_mut().expect("just pushed")
    }

    pub fn edge(&mut self, from: GraphRef, rel: &str, to: GraphRef) -> &mut GraphEdge {
        self.edges.push(GraphEdge { from, rel: rel.to_owned(), to, ..Default::default() });
        self.edges.last_mut().expect("just pushed")
    }

    fn len(&self) -> usize {
        self.nodes.len() + self.edges.len()
    }
}

/// What one look wrote: units in order, in one layer, seen at one time.
#[derive(Default, Debug, Clone)]
pub struct Batch {
    pub units: Vec<Unit>,
    pub layer: GraphLayer,
    pub at_ms: Option<u64>,
}

impl Batch {
    pub fn new() -> Self {
        Batch::default()
    }

    pub fn in_layer(layer: GraphLayer) -> Self {
        Batch { layer, ..Default::default() }
    }

    /// A new unit, to fill.
    pub fn unit(&mut self) -> &mut Unit {
        self.units.push(Unit::default());
        self.units.last_mut().expect("just pushed")
    }

    pub fn extend(&mut self, other: Batch) {
        self.units.extend(other.units);
    }

    pub fn is_empty(&self) -> bool {
        self.units.iter().all(|u| u.len() == 0)
    }

    /// The nodes this batch writes.
    pub fn refs(&self) -> HashSet<GraphRef> {
        self.units.iter().flat_map(|u| u.nodes.iter().map(|n| r(&n.label, n.key.clone()))).collect()
    }

    /// The puts it takes, at most [`MAX_ITEMS`] each, units kept whole where they fit.
    fn calls(self) -> Vec<GraphPutParams> {
        let (layer, at_ms) = (self.layer, self.at_ms);
        let mut out = Vec::new();
        let mut current = GraphPutParams { layer, at_ms, ..Default::default() };
        let size = |p: &GraphPutParams| p.nodes.len() + p.edges.len();
        for unit in self.units {
            if unit.len() == 0 {
                continue;
            }
            if size(&current) + unit.len() > MAX_ITEMS && size(&current) > 0 {
                out.push(std::mem::replace(&mut current, GraphPutParams { layer, at_ms, ..Default::default() }));
            }
            if unit.len() > MAX_ITEMS {
                // Builders keep units under the limit (a repository's packages go in slices); a
                // bigger one is sent in pieces, which memory may refuse in part.
                tracing::warn!("a graph unit of {} items is split", unit.len());
                for node in unit.nodes {
                    if size(&current) >= MAX_ITEMS {
                        out.push(std::mem::replace(&mut current, GraphPutParams { layer, at_ms, ..Default::default() }));
                    }
                    current.nodes.push(node);
                }
                for edge in unit.edges {
                    if size(&current) >= MAX_ITEMS {
                        out.push(std::mem::replace(&mut current, GraphPutParams { layer, at_ms, ..Default::default() }));
                    }
                    current.edges.push(edge);
                }
                continue;
            }
            current.nodes.extend(unit.nodes);
            current.edges.extend(unit.edges);
        }
        if size(&current) > 0 {
            out.push(current);
        }
        out
    }
}

// ---------------------------------------------------------------------------------------------
// Writing

fn enqueue(op: Op) {
    {
        let mut outbox = lock(&OUTBOX);
        outbox.push_back(op);
        while outbox.len() > BACKLOG {
            // Never remove the write whose response the writer is awaiting. Otherwise its
            // acknowledgement could pop a different, unsent write from the queue.
            let index = usize::from(SENDING.load(Ordering::SeqCst));
            outbox.remove(index);
            DROPPED.fetch_add(1, Ordering::SeqCst);
            tracing::warn!("memory has been away too long: the oldest graph write was dropped");
        }
    }
    WAKE.notify_one();
}

/// Write a batch (in order with every other write). Nothing is written before [`ready`].
pub fn put(batch: Batch) {
    if batch.is_empty() {
        return;
    }
    for call in batch.calls() {
        enqueue(Op::Put(call));
    }
}

/// Mark nodes as gone (their history stays).
pub fn retire(refs: Vec<GraphRef>, reason: &str) {
    for chunk in refs.chunks(MAX_ITEMS) {
        enqueue(Op::Retire(GraphRetireParams { refs: chunk.to_vec(), reason: Some(reason.to_owned()), at_ms: None }));
    }
}

/// Append records to a stream (created with `retention_days` on first use).
pub fn append(topic: &str, records: Vec<Value>, retention_days: u32) {
    for chunk in records.chunks(1000) {
        enqueue(Op::Append(StreamAppendParams { topic: topic.to_owned(), records: chunk.to_vec(), retention_days: Some(retention_days) }));
    }
}

/// Wait until every write so far was sent (or `limit` passed). True when the outbox is empty.
pub async fn flush(limit: Duration) -> bool {
    let deadline = Instant::now() + limit;
    loop {
        if lock(&OUTBOX).is_empty() && !SENDING.load(Ordering::SeqCst) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        WAKE.notify_one();
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How many writes memory refused so far.
pub fn refused() -> usize {
    REFUSED.load(Ordering::SeqCst)
}

/// Actual outbox overflows, visible to protection health instead of only the session log.
pub fn dropped() -> usize { DROPPED.load(Ordering::SeqCst) }

/// Writes waiting for memory.
pub fn pending() -> usize {
    lock(&OUTBOX).len()
}

/// Whether memory would take this call later: it is away, busy or slow.
fn retry_later(error: &cc_protocol::RpcError) -> bool {
    use cc_protocol::codes;
    error.retryable
        || [codes::UNAVAILABLE, codes::TIMEOUT, codes::BUSY, codes::DRAINING, codes::CONNECTION_CLOSED].contains(&error.code.as_str())
}

/// The writer: sends the outbox in order, waits and tries again while memory is away.
async fn writer(ctx: Ctx) {
    let mut failures = 0u32;
    loop {
        let next = {
            let outbox = lock(&OUTBOX);
            outbox.front().map(|op| {
                SENDING.store(true, Ordering::SeqCst);
                op.call()
            })
        };
        let Some((method, params)) = next else {
            let _ = tokio::time::timeout(Duration::from_secs(5), WAKE.notified()).await;
            continue;
        };
        let outcome = tokio::time::timeout(CALL_LIMIT, ctx.call(method, params)).await;
        let done = match outcome {
            Ok(Ok(_)) => true,
            Ok(Err(error)) if !retry_later(&error) && (error.code != cc_protocol::codes::INTERNAL || failures >= 5) => {
                tracing::warn!("{method} refused: {}", error.message);
                REFUSED.fetch_add(1, Ordering::SeqCst);
                true
            }
            Ok(Err(error)) => {
                tracing::info!("{method}: {} (tried again in a moment)", error.message);
                false
            }
            Err(_) => {
                tracing::info!("{method}: no answer in {} s (tried again in a moment)", CALL_LIMIT.as_secs());
                false
            }
        };
        if done {
            failures = 0;
            let mut outbox = lock(&OUTBOX);
            outbox.pop_front();
            SENDING.store(false, Ordering::SeqCst);
        } else {
            failures += 1;
            SENDING.store(false, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(if failures < 3 { 2 } else { 5 })).await;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Reading

fn ctx() -> Result<Ctx, String> {
    CTX.get().cloned().ok_or_else(|| "not connected to the frame".to_owned())
}

/// A call to memory with a time limit.
pub async fn call(method: &str, params: Value) -> Result<Value, String> {
    let ctx = ctx()?;
    match tokio::time::timeout(CALL_LIMIT, ctx.call(method, params)).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{method}: {}", error.message)),
        Err(_) => Err(format!("{method}: no answer within {} s", CALL_LIMIT.as_secs())),
    }
}

/// One read-only statement: its rows (at most 5000).
pub async fn query(cypher: &str, params: Value) -> Result<Vec<Vec<Value>>, String> {
    let answer = call(methods::GRAPH_QUERY, json!({"cypher": cypher, "params": params, "limit": PAGE})).await?;
    Ok(answer["rows"].as_array().into_iter().flatten().map(|row| row.as_array().cloned().unwrap_or_default()).collect())
}

/// Every row of a statement that ends in `ORDER BY …` (pages of 5000 with `SKIP`).
pub async fn query_all(cypher: &str, params: Value) -> Result<Vec<Vec<Value>>, String> {
    let mut rows = Vec::new();
    let mut params = if params.is_object() { params } else { json!({}) };
    for page in 0.. {
        params["_skip"] = json!(page * PAGE);
        let got = query(&format!("{cypher} SKIP $_skip LIMIT {PAGE}"), params.clone()).await?;
        let full = got.len() as u64 == PAGE;
        rows.extend(got);
        if !full {
            break;
        }
    }
    Ok(rows)
}

/// A stream's records since a time (all that are kept when 0), in order.
pub async fn stream_read(topic: &str, since_ms: u64) -> Result<Vec<StreamEntry>, String> {
    let mut out = Vec::new();
    let mut from: Option<u64> = None;
    loop {
        let mut params = json!({"topic": topic, "limit": 5000});
        match from {
            Some(offset) => params["from_offset"] = json!(offset),
            None if since_ms > 0 => params["since_ms"] = json!(since_ms),
            None => {}
        }
        let read: StreamReadResult = serde_json::from_value(call(methods::STREAM_READ, params).await?).map_err(|e| e.to_string())?;
        let got = read.records.len();
        out.extend(read.records);
        if read.end || got == 0 {
            break;
        }
        from = Some(read.next_offset);
    }
    Ok(out)
}

/// Run a read from a blocking thread (a sweep check, a watcher's tick).
pub fn block<T>(work: impl Future<Output = T>) -> Option<T> {
    let handle = tokio::runtime::Handle::try_current().ok()?;
    Some(handle.block_on(work))
}

/// Text of a cell (empty for null or another type).
pub fn text(value: &Value) -> String {
    value.as_str().unwrap_or("").to_owned()
}

/// A list-of-text cell.
pub fn texts(value: &Value) -> Vec<String> {
    value.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect()
}

pub fn number(value: &Value) -> u64 {
    value.as_u64().or_else(|| value.as_f64().map(|f| f.max(0.0) as u64)).unwrap_or(0)
}

// ---------------------------------------------------------------------------------------------
// Starting

/// Whether memory answered and everything kept was loaded: baselines can be compared and written.
pub fn ready() -> bool {
    READY.load(Ordering::SeqCst)
}

/// Wait until [`ready`], at most `limit`.
pub async fn wait_ready(limit: Duration) -> bool {
    if ready() {
        return true;
    }
    let _ = tokio::time::timeout(limit, async {
        while !ready() {
            let notified = READY_SIGNAL.notified();
            if ready() {
                break;
            }
            let _ = tokio::time::timeout(Duration::from_millis(500), notified).await;
        }
    })
    .await;
    ready()
}

pub fn set_ready() {
    READY.store(true, Ordering::SeqCst);
    READY_SIGNAL.notify_waiters();
}

/// Start the writer and wait for this Mac's root node (memory may start after this plugin).
/// Called once, when the frame connection is known.
pub async fn connect(ctx: Ctx) {
    if CTX.set(ctx.clone()).is_err() {
        return;
    }
    tokio::spawn(writer(ctx));
    let mut waited = 0u32;
    loop {
        match call(methods::GRAPH_MACHINE, json!({})).await {
            Ok(answer) => {
                if let Some(key) = answer["key"].as_str().filter(|k| !k.is_empty()) {
                    let _ = MACHINE.set(key.to_owned());
                    return;
                }
            }
            Err(error) if waited % 20 == 0 => tracing::info!("memory is not answering yet ({error}); waiting"),
            Err(_) => {}
        }
        waited += 1;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
}

/// `kind:` and 16 hex of SHA-256 of the text: a stable key for something known by its words.
pub fn hashed(prefix: &str, text: &str) -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(text.as_bytes());
    let hex: String = digest.iter().take(8).map(|b| format!("{b:02x}")).collect();
    format!("{prefix}:{hex}")
}

/// The chain of `Folder` nodes from `path` up to the home folder (as the memory plugin writes a
/// project's folders), or up to `/` outside it, each `IN` its parent. Returns the folder's ref.
pub fn folder(unit: &mut Unit, path: &std::path::Path) -> GraphRef {
    let home = crate::util::home();
    let mut chain: Vec<String> = Vec::new();
    for p in path.ancestors() {
        let text = p.display().to_string();
        if text.is_empty() {
            continue;
        }
        chain.push(text);
        if path.starts_with(&home) && p == home {
            break;
        }
    }
    if chain.is_empty() {
        chain.push("/".into());
    }
    for key in &chain {
        unit.node("Folder", key.clone());
    }
    for pair in chain.windows(2) {
        unit.edge(r("Folder", pair[0].clone()), "IN", r("Folder", pair[1].clone()));
    }
    if chain.len() == 1 && let Some(machine) = machine() {
        // A top folder alone has no parent to connect it.
        unit.edge(r("Folder", chain[0].clone()), "ON", machine);
    }
    r("Folder", chain[0].clone())
}

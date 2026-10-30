//! Traces: a week of what a process tree did. The system plugin records them and writes them
//! here; `system.trace.*` reads them back. They live in their own IronGraph project, `traces`,
//! never with memory (memory is never shared; traces are lent over the mesh).
//!
//! ```text
//! stream  `trace.<id>`: one JSON TraceRecord per record, in time order, kept 7 days
//! (:Trace {id, label, command, cwd, pid, source, run_id, asked_by, started, ended, exit_code,
//!          limits, records, errors: a list of the first error lines})
//!     cpu, memory, gpu, disk_write: temporal, the whole tree at each scan
//! (:Process {id, trace, name, command, count, cpu_max, memory_max, first, last})
//!     one per program name in the trace ("rustc", 304 of them); cpu: temporal, all of them summed
//! (:Folder | :Host | :Port {id, trace, kind, name, count, first, last})
//! (t)-[:RAN]->(p)   (p)-[:SPAWNED {count}]->(p)   (p)-[:READ | :WROTE {count}]->(:Folder)
//! (p)-[:CONNECTED {count}]->(:Host)   (p)-[:LISTENED {count}]->(:Port)
//! ```
//!
//! Processes are grouped by name and files by folder, so a build that runs 300 compilers over
//! 3,000 files is a handful of nodes; the stream keeps every record. A one-minute rollup per
//! temporal metric keeps the summary cheap on a long trace.

use crate::db::{Graph, Rows, layer};
use crate::params;
use cc_protocol::RpcError;
use cc_protocol::contracts::memory::{
    TraceEdge, TraceGraph, TraceInfo, TraceMetric, TraceNode, TracePhase, TracePoint, TraceProcesses, TraceRecord, TraceSummary, TraceTouched, TraceWindow,
};
use cc_protocol::contracts::now_ms;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt::Write as _;
use std::sync::Arc;
use tokio::sync::Mutex;

/// The IronGraph project traces live in.
pub const PROJECT: &str = "traces";
/// How long a trace is kept after it ends.
pub const KEEP_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// Error lines kept per trace.
const ERRORS: usize = 20;
/// Distinct files counted per folder, so a folder's count stays bounded in this process's memory.
const FILES_SEEN: usize = 200_000;

const TRACE_FIELDS: &str = "t.id, t.label, t.command, t.cwd, t.pid, t.source, t.run_id, t.asked_by, t.started, t.ended, t.exit_code, t.limits, t.records";

pub struct TraceStore {
    graph: Arc<Graph>,
    ig: String,
    /// Statements done once per process: temporal declarations and rollups, by name.
    declared: Mutex<HashSet<String>>,
    /// Topics created by this process.
    topics: Mutex<HashSet<String>>,
    /// (trace, pid) -> program name, from `start` records: what a child's SPAWNED edge starts at.
    names: Mutex<HashMap<(String, u32), String>>,
    /// (trace, path) of every file counted in its folder.
    files: Mutex<HashSet<(String, String)>>,
}

impl TraceStore {
    pub async fn open(graph: Arc<Graph>) -> Result<Self, RpcError> {
        let ig = graph.ensure_project(PROJECT).await?;
        let store = TraceStore {
            graph,
            ig,
            declared: Mutex::new(HashSet::new()),
            topics: Mutex::new(HashSet::new()),
            names: Mutex::new(HashMap::new()),
            files: Mutex::new(HashSet::new()),
        };
        store.migrate_errors().await?;
        Ok(store)
    }

    /// Rewrite `errors` an earlier version kept as JSON text as a list (none when empty).
    async fn migrate_errors(&self) -> Result<(), RpcError> {
        let rows = self.read("MATCH (t:Trace) WHERE t.errors STARTS WITH '[' RETURN t.id, t.errors", Map::new()).await?;
        for row in &rows.rows {
            let Some(id) = row.first().and_then(Value::as_str) else { continue };
            let lines = Self::error_lines(row.get(1));
            let value = if lines.is_empty() { Value::Null } else { json!(lines) };
            self.write("MATCH (t:Trace {id: $id}) SET t.errors = $errors", params! { "id" => id, "errors" => value }).await?;
        }
        Ok(())
    }

    async fn write(&self, cypher: &str, params: Map<String, Value>) -> Result<Rows, RpcError> {
        self.graph.run(&self.ig, &format!("{} {cypher}", layer::OBSERVED_WRITE), params).await
    }

    async fn read(&self, cypher: &str, params: Map<String, Value>) -> Result<Rows, RpcError> {
        self.graph.run(&self.ig, &format!("{} {cypher}", layer::OBSERVED_READ), params).await
    }

    /// Run a schema statement once per process; "already exists" counts as done.
    async fn once(&self, key: &str, cypher: &str) -> Result<(), RpcError> {
        if self.declared.lock().await.contains(key) {
            return Ok(());
        }
        match self.graph.run(&self.ig, cypher, Map::new()).await {
            Ok(_) => {}
            Err(error) if error.message.contains("already exists") => {}
            Err(error) => return Err(error),
        }
        self.declared.lock().await.insert(key.to_owned());
        Ok(())
    }

    /// Create or update a trace and add its records.
    pub async fn append(&self, mut info: TraceInfo, records: Vec<TraceRecord>) -> Result<TraceInfo, RpcError> {
        validate_id(&info.id)?;
        let id = info.id.clone();
        let topic = topic_of(&id);
        if !self.topics.lock().await.contains(&topic) {
            self.graph.run(&self.ig, &format!("CREATE TOPIC `{topic}` PARTITIONS 1 RETENTION 7 DAYS"), Map::new()).await?;
            self.topics.lock().await.insert(topic.clone());
        }
        // The header. Temporal properties need a first ordinary write before they are declared.
        self.write(
            "MERGE (t:Trace {id: $id}) ON CREATE SET t.records = 0, t.cpu = 0.0, t.memory = 0, t.gpu = 0.0, t.disk_write = 0 \
             SET t.label = $label, t.command = $command, t.cwd = $cwd, t.pid = $pid, t.source = $source, t.run_id = $run_id, \
                 t.asked_by = $asked_by, t.started = $started, t.ended = $ended, t.limits = $limits, t.records = t.records + $count",
            params! {
                "id" => id, "label" => info.label, "command" => info.command, "cwd" => info.cwd, "pid" => info.pid, "source" => info.source,
                "run_id" => info.run_id, "asked_by" => info.asked_by, "started" => info.started, "ended" => info.ended, "limits" => info.limits,
                "count" => records.len()
            },
        )
        .await?;
        for (property, kind) in [("cpu", "FLOAT"), ("memory", "INTEGER"), ("gpu", "FLOAT"), ("disk_write", "INTEGER")] {
            self.once(&format!("temporal Trace.{property}"), &format!("ALTER NODE PROPERTY Trace.{property} SET TEMPORAL {kind} RETENTION duration('P8D')")).await?;
            self.once(
                &format!("rollup Trace.{property}"),
                &format!("CREATE ROLLUP trace_{property}_minute FOR (t:Trace) ON t.{property} WINDOW TUMBLING duration('PT1M') AGGREGATE avg, min, max, count"),
            )
            .await?;
        }
        if records.is_empty() {
            return self.info(&id).await?.ok_or_else(|| RpcError::internal(format!("trace {id} missing after it was written")));
        }
        let bytes = records.iter().map(|record| serde_json::to_vec(record).unwrap_or_default()).collect();
        self.graph.stream_append(&self.ig, &topic, bytes).await?;

        self.processes(&id, &records).await?;
        self.samples(&id, &records).await?;
        self.touched(&id, &records).await?;
        self.errors(&id, &records).await?;
        if let Some(code) = records.iter().rev().find(|record| record.kind == "exit").and_then(|record| record.code) {
            self.write("MATCH (t:Trace {id: $id}) SET t.exit_code = $code", params! { "id" => id, "code" => code }).await?;
            info.exit_code = Some(code);
        }
        self.info(&id).await?.ok_or_else(|| RpcError::internal(format!("trace {id} missing after it was written")))
    }

    /// `start` records: one Process node per name, counted, with the SPAWNED edge from its parent's.
    async fn processes(&self, id: &str, records: &[TraceRecord]) -> Result<(), RpcError> {
        let mut starts = Vec::new();
        {
            let mut names = self.names.lock().await;
            for record in records.iter().filter(|record| record.kind == "start" && !record.name.is_empty()) {
                let parent = names.get(&(id.to_owned(), record.ppid)).cloned();
                names.insert((id.to_owned(), record.pid), record.name.clone());
                starts.push(json!({
                    "pid": process_id(id, &record.name), "name": record.name, "command": record.text, "at": record.at,
                    "parent": parent.filter(|parent| parent != &record.name).map(|parent| process_id(id, &parent)),
                }));
            }
        }
        if starts.is_empty() {
            return Ok(());
        }
        self.write(
            "UNWIND $starts AS s MATCH (t:Trace {id: $id}) \
             MERGE (p:Process {id: s.pid}) ON CREATE SET p.trace = $id, p.name = s.name, p.command = s.command, p.count = 0, p.cpu = 0.0, \
                 p.cpu_max = 0.0, p.memory_max = 0, p.first = s.at, p.last = s.at \
             SET p.count = p.count + 1 \
             MERGE (t)-[:RAN]->(p)",
            params! { "id" => id, "starts" => starts },
        )
        .await?;
        let spawned: Vec<&Value> = starts.iter().filter(|start| start["parent"].is_string()).collect();
        if !spawned.is_empty() {
            self.write(
                "UNWIND $spawned AS s MATCH (a:Process {id: s.parent}), (b:Process {id: s.pid}) \
                 MERGE (a)-[e:SPAWNED]->(b) ON CREATE SET e.count = 0 SET e.count = e.count + 1",
                params! { "spawned" => spawned },
            )
            .await?;
        }
        self.once("temporal Process.cpu", "ALTER NODE PROPERTY Process.cpu SET TEMPORAL FLOAT RETENTION duration('P8D')").await?;
        self.once("rollup Process.cpu", "CREATE ROLLUP process_cpu_minute FOR (p:Process) ON p.cpu WINDOW TUMBLING duration('PT1M') AGGREGATE avg, max, count").await
    }

    /// `sample` records: the tree's totals on the Trace and each name's sum on its Process, one
    /// temporal sample per scan.
    async fn samples(&self, id: &str, records: &[TraceRecord]) -> Result<(), RpcError> {
        #[derive(Default)]
        struct Sum {
            cpu: f64,
            memory: u64,
            gpu: f64,
            disk_write: u64,
            peak_cpu: f64,
            peak_memory: u64,
        }
        let mut totals: BTreeMap<u64, Sum> = BTreeMap::new();
        let mut named: BTreeMap<(u64, String), Sum> = BTreeMap::new();
        let names = self.names.lock().await;
        for record in records.iter().filter(|record| record.kind == "sample") {
            let (cpu, memory) = (f64::from(record.cpu.unwrap_or(0.0)), record.memory.unwrap_or(0));
            let total = totals.entry(record.at).or_default();
            total.cpu += cpu;
            total.memory += memory;
            total.gpu += f64::from(record.gpu.unwrap_or(0.0));
            total.disk_write += record.disk_write.unwrap_or(0);
            let name = if record.name.is_empty() { names.get(&(id.to_owned(), record.pid)).cloned().unwrap_or_default() } else { record.name.clone() };
            if name.is_empty() {
                continue;
            }
            let sum = named.entry((record.at, name)).or_default();
            sum.cpu += cpu;
            sum.memory += memory;
            sum.peak_cpu = sum.peak_cpu.max(cpu);
            sum.peak_memory = sum.peak_memory.max(memory);
        }
        drop(names);
        if totals.is_empty() {
            return Ok(());
        }
        let totals: Vec<Value> =
            totals.into_iter().map(|(at, s)| json!({"at": at, "cpu": s.cpu, "memory": s.memory, "gpu": s.gpu.min(100.0), "disk_write": s.disk_write})).collect();
        self.write(
            "UNWIND $totals AS s MATCH (t:Trace {id: $id}) \
             SET t.cpu = s.cpu AT TIME datetime.fromepochmillis(s.at), t.memory = s.memory AT TIME datetime.fromepochmillis(s.at), \
                 t.gpu = s.gpu AT TIME datetime.fromepochmillis(s.at), t.disk_write = s.disk_write AT TIME datetime.fromepochmillis(s.at)",
            params! { "id" => id, "totals" => totals },
        )
        .await?;
        let named: Vec<Value> = named
            .into_iter()
            .map(|((at, name), s)| json!({"pid": process_id(id, &name), "at": at, "cpu": s.cpu, "peak_cpu": s.peak_cpu, "peak_memory": s.peak_memory}))
            .collect();
        self.write(
            "UNWIND $named AS s MATCH (p:Process {id: s.pid}) \
             SET p.cpu = s.cpu AT TIME datetime.fromepochmillis(s.at), p.last = s.at, \
                 p.cpu_max = CASE WHEN s.peak_cpu > p.cpu_max THEN s.peak_cpu ELSE p.cpu_max END, \
                 p.memory_max = CASE WHEN s.peak_memory > p.memory_max THEN s.peak_memory ELSE p.memory_max END",
            params! { "named" => named },
        )
        .await?;
        Ok(())
    }

    /// `open`, `connect` and `listen` records: folders, hosts and ports, and how each name used them.
    async fn touched(&self, id: &str, records: &[TraceRecord]) -> Result<(), RpcError> {
        let names = self.names.lock().await;
        let mut files = self.files.lock().await;
        // (edge type, label, kind) -> rows
        let mut groups: BTreeMap<(&str, &str, &str), Vec<Value>> = BTreeMap::new();
        for record in records {
            let Some(name) = names.get(&(id.to_owned(), record.pid)) else { continue };
            let (edge, label, kind, target, new) = match record.kind.as_str() {
                "open" => {
                    let folder = folder_of(&record.text);
                    let new = files.len() < FILES_SEEN && files.insert((id.to_owned(), record.text.clone()));
                    let edge = if record.mode.contains('w') || record.mode.contains('u') { "WROTE" } else { "READ" };
                    (edge, "Folder", "folder", folder, new)
                }
                "connect" => ("CONNECTED", "Host", "host", record.text.clone(), true),
                "listen" => ("LISTENED", "Port", "port", record.text.clone(), true),
                _ => continue,
            };
            groups.entry((edge, label, kind)).or_default().push(json!({
                "pid": process_id(id, name), "node": format!("{id}|{kind}|{target}"), "name": target, "at": record.at, "new": u32::from(new),
            }));
        }
        drop((names, files));
        for ((edge, label, kind), rows) in groups {
            self.write(
                &format!(
                    "UNWIND $rows AS r MATCH (p:Process {{id: r.pid}}) \
                     MERGE (n:{label} {{id: r.node}}) ON CREATE SET n.trace = $id, n.kind = $kind, n.name = r.name, n.count = 0, n.first = r.at \
                     SET n.count = n.count + r.new, n.last = r.at \
                     MERGE (p)-[e:{edge}]->(n) ON CREATE SET e.count = 0 SET e.count = e.count + 1"
                ),
                params! { "id" => id, "kind" => kind, "rows" => rows },
            )
            .await?;
        }
        Ok(())
    }

    /// A trace's `errors`: a list of strings (an earlier version kept JSON text, read here too and
/// rewritten as a list by the next write).
fn error_lines(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(list)) => list.iter().filter_map(Value::as_str).map(str::to_owned).collect(),
        Some(Value::String(text)) => serde_json::from_str(text).unwrap_or_default(),
        _ => Vec::new(),
    }
}

/// `output` lines that look like errors or warnings, the first [`ERRORS`] of them.
    async fn errors(&self, id: &str, records: &[TraceRecord]) -> Result<(), RpcError> {
        let found: Vec<&str> = records.iter().filter(|record| record.kind == "output" && looks_wrong(&record.text)).map(|record| record.text.as_str()).collect();
        if found.is_empty() {
            return Ok(());
        }
        let rows = self.read("MATCH (t:Trace {id: $id}) RETURN t.errors", params! { "id" => id }).await?;
        let mut kept = Self::error_lines(rows.rows.first().and_then(|row| row.first()));
        if kept.len() >= ERRORS {
            return Ok(());
        }
        kept.extend(found.into_iter().take(ERRORS - kept.len()).map(|line| line.chars().take(300).collect::<String>()));
        self.write("MATCH (t:Trace {id: $id}) SET t.errors = $errors", params! { "id" => id, "errors" => kept }).await?;
        Ok(())
    }

    pub async fn info(&self, id: &str) -> Result<Option<TraceInfo>, RpcError> {
        let rows = self.read(&format!("MATCH (t:Trace {{id: $id}}) RETURN {TRACE_FIELDS}"), params! { "id" => id }).await?;
        Ok(rows.rows.first().map(|row| info_from(row)))
    }

    /// The traces kept, newest first; those that ended more than a week ago are deleted first.
    pub async fn list(&self, limit: u32) -> Result<Vec<TraceInfo>, RpcError> {
        let horizon = now_ms().saturating_sub(KEEP_MS);
        let old = self
            .read("MATCH (t:Trace) WHERE coalesce(t.ended, t.started) < $horizon RETURN t.id", params! { "horizon" => horizon })
            .await?;
        for id in old.column(0).filter_map(Value::as_str).map(str::to_owned).collect::<Vec<_>>() {
            self.delete(&id).await?;
        }
        let limit = if limit == 0 { 100 } else { limit.min(1000) };
        let rows = self.read(&format!("MATCH (t:Trace) RETURN {TRACE_FIELDS} ORDER BY t.started DESC LIMIT {limit}"), Map::new()).await?;
        Ok(rows.rows.iter().map(|row| info_from(row)).collect())
    }

    pub async fn delete(&self, id: &str) -> Result<(), RpcError> {
        validate_id(id)?;
        self.write("MATCH (n) WHERE n.trace = $id DETACH DELETE n", params! { "id" => id }).await?;
        self.write("MATCH (t:Trace {id: $id}) DETACH DELETE t", params! { "id" => id }).await?;
        self.graph.drop_topic(&self.ig, &topic_of(id)).await?;
        self.topics.lock().await.remove(&topic_of(id));
        self.names.lock().await.retain(|(trace, _), _| trace != id);
        self.files.lock().await.retain(|(trace, _)| trace != id);
        Ok(())
    }

    /// One metric of the whole tree over `from..to`: min, average, 95th percentile, and the peak
    /// with its time.
    async fn metric(&self, id: &str, name: &str, from: u64, to: u64) -> Result<Option<TraceMetric>, RpcError> {
        let history = format!("MATCH (t:Trace {{id: $id}}) HISTORY t.{name} FROM datetime.fromepochmillis($from) TO datetime.fromepochmillis($to) AS s");
        let span = params! { "id" => id, "from" => from, "to" => to + 1 };
        let rows = self.read(&format!("{history} RETURN count(s), min(s.value), avg(s.value), percentileCont(s.value, 0.95), max(s.value)"), span.clone()).await?;
        let Some(row) = rows.rows.first() else { return Ok(None) };
        if number(row.first()) == 0.0 {
            return Ok(None);
        }
        let peak = self.read(&format!("{history} RETURN s.time ORDER BY s.value DESC LIMIT 1"), span).await?;
        let max_at = peak.rows.first().map(|row| (number(row.first()) / 1_000_000.0) as u64).unwrap_or(from);
        Ok(Some(TraceMetric { name: name.into(), min: number(row.get(1)), avg: number(row.get(2)), p95: number(row.get(3)), max: number(row.get(4)), max_at }))
    }

    /// Stretches where the tree's CPU stayed at one level: windows of a 24th of the span (8 s at
    /// least), neighbours at a similar level joined, at most six.
    async fn phases(&self, id: &str, from: u64, to: u64) -> Result<Vec<TracePhase>, RpcError> {
        let width_ms = ((to.saturating_sub(from)) / 24).max(8_000);
        let span = params! { "id" => id, "from" => from, "to" => to + 1 };
        let window = format!(
            "MATCH (t:Trace {{id: $id}}) HISTORY t.{{metric}} FROM datetime.fromepochmillis($from) TO datetime.fromepochmillis($to) AS s \
             WINDOW TUMBLING duration('PT{}S') ON s.time AS w WITH w, s RETURN w.start, avg(s.value), max(s.value) ORDER BY w.start",
            width_ms / 1000
        );
        let cpu = self.read(&window.replace("{metric}", "cpu"), span.clone()).await?;
        let memory = self.read(&window.replace("{metric}", "memory"), span).await?;
        let memory: HashMap<u64, u64> = memory.rows.iter().map(|row| ((number(row.first()) / 1_000_000.0) as u64, number(row.get(2)) as u64)).collect();
        let windows: Vec<(u64, f64, u64)> = cpu
            .rows
            .iter()
            .map(|row| {
                let start = (number(row.first()) / 1_000_000.0) as u64;
                (start, number(row.get(1)), memory.get(&start).copied().unwrap_or(0))
            })
            .collect();
        let peak = windows.iter().map(|w| w.1).fold(0.0, f64::max);
        let near = (peak * 0.2).max(25.0);
        // (from, to, cpu × ms, ms, memory)
        let mut runs: Vec<(u64, u64, f64, f64, u64)> = Vec::new();
        for (start, cpu, memory) in windows {
            let end = (start + width_ms).min(to);
            let ms = end.saturating_sub(start.max(from)).max(1) as f64;
            match runs.last_mut() {
                Some(last) if (last.2 / last.3 - cpu).abs() <= near => {
                    last.1 = end;
                    last.2 += cpu * ms;
                    last.3 += ms;
                    last.4 = last.4.max(memory);
                }
                _ => runs.push((start.max(from), end, cpu * ms, ms, memory)),
            }
        }
        // At most six: join the neighbours whose levels are closest.
        while runs.len() > 6 {
            let at = (0..runs.len() - 1)
                .min_by(|&a, &b| {
                    let gap = |i: usize| (runs[i].2 / runs[i].3 - runs[i + 1].2 / runs[i + 1].3).abs();
                    gap(a).total_cmp(&gap(b))
                })
                .unwrap_or(0);
            let next = runs.remove(at + 1);
            let run = &mut runs[at];
            run.1 = next.1;
            run.2 += next.2;
            run.3 += next.3;
            run.4 = run.4.max(next.4);
        }
        let mut phases = Vec::new();
        for (start, end, weighted, ms, memory) in runs {
            let busiest = self
                .read(
                    "MATCH (p:Process {trace: $id}) HISTORY p.cpu FROM datetime.fromepochmillis($from) TO datetime.fromepochmillis($to) AS s \
                     WITH p, avg(s.value) AS cpu WHERE cpu >= 1 RETURN p.name, cpu ORDER BY cpu DESC LIMIT 3",
                    params! { "id" => id, "from" => start, "to" => end + 1 },
                )
                .await?;
            let busiest = busiest.rows.iter().map(|row| format!("{} {:.0}%", row.first().and_then(Value::as_str).unwrap_or("?"), number(row.get(1)))).collect();
            phases.push(TracePhase { from: start, to: end, cpu: weighted / ms, memory, busiest });
        }
        Ok(phases)
    }

    /// The tree over `from..to` in about 120 buckets (4 s at least): CPU and GPU averaged, memory
    /// at its peak.
    async fn series(&self, id: &str, from: u64, to: u64) -> Result<Vec<TracePoint>, RpcError> {
        let width_s = ((to.saturating_sub(from)) / 120_000).max(4);
        let span = params! { "id" => id, "from" => from, "to" => to + 1 };
        let mut points: BTreeMap<u64, TracePoint> = BTreeMap::new();
        for (metric, take) in [("cpu", "avg(s.value)"), ("memory", "max(s.value)"), ("gpu", "avg(s.value)")] {
            let rows = self
                .read(
                    &format!(
                        "MATCH (t:Trace {{id: $id}}) HISTORY t.{metric} FROM datetime.fromepochmillis($from) TO datetime.fromepochmillis($to) AS s \
                         WINDOW TUMBLING duration('PT{width_s}S') ON s.time AS w WITH w, s RETURN w.start, {take} ORDER BY w.start"
                    ),
                    span.clone(),
                )
                .await?;
            for row in &rows.rows {
                let at = ((number(row.first()) / 1_000_000.0) as u64).max(from);
                let point = points.entry(at).or_insert_with(|| TracePoint { at, ..Default::default() });
                let value = number(row.get(1));
                match metric {
                    "cpu" => point.cpu = value,
                    "memory" => point.memory = value as u64,
                    _ => point.gpu = Some(value),
                }
            }
        }
        Ok(points.into_values().collect())
    }

    pub async fn summary(&self, id: &str, from: Option<u64>, to: Option<u64>) -> Result<TraceSummary, RpcError> {
        let info = self.info(id).await?.ok_or_else(|| RpcError::not_found(format!("no trace {id}")))?;
        let from = from.unwrap_or(info.started).max(info.started);
        let to = to.unwrap_or_else(|| info.ended.unwrap_or_else(now_ms)).max(from);
        let mut metrics = Vec::new();
        for name in ["cpu", "memory", "gpu", "disk_write"] {
            metrics.extend(self.metric(id, name, from, to).await?);
        }
        let phases = self.phases(id, from, to).await?;
        let series = self.series(id, from, to).await?;
        let rows = self
            .read("MATCH (p:Process {trace: $id}) RETURN p.name, p.count, p.cpu_max, p.memory_max ORDER BY p.cpu_max DESC LIMIT 12", params! { "id" => id })
            .await?;
        let processes: Vec<TraceProcesses> = rows
            .rows
            .iter()
            .map(|row| TraceProcesses { name: text(row.first()), count: number(row.get(1)) as u32, cpu: number(row.get(2)), memory: number(row.get(3)) as u64 })
            .collect();
        let rows = self
            .read(
                "MATCH (p:Process {trace: $id})-[e]->(n) WHERE n.trace = $id AND n.kind IS NOT NULL \
                 RETURN n.kind, n.name, type(e), n.count, n.first, n.last, sum(e.count) AS uses ORDER BY uses DESC LIMIT 12",
                params! { "id" => id },
            )
            .await?;
        let touched: Vec<TraceTouched> = rows
            .rows
            .iter()
            .map(|row| TraceTouched {
                kind: text(row.first()),
                name: text(row.get(1)),
                how: text(row.get(2)).to_lowercase(),
                count: number(row.get(3)) as u32,
                first: number(row.get(4)) as u64,
                last: number(row.get(5)) as u64,
            })
            .collect();
        let rows = self.read("MATCH (t:Trace {id: $id}) RETURN t.errors", params! { "id" => id }).await?;
        let errors = Self::error_lines(rows.rows.first().and_then(|row| row.first()));
        let mut summary = TraceSummary { trace: info, from, to, metrics, series, phases, processes, touched, errors, text: String::new() };
        summary.text = render(&summary);
        Ok(summary)
    }

    pub async fn graph(&self, id: &str) -> Result<TraceGraph, RpcError> {
        let nodes = self
            .read("MATCH (n) WHERE n.trace = $id RETURN n.id, coalesce(n.kind, 'process'), n.name, n.count ORDER BY n.count DESC LIMIT 400", params! { "id" => id })
            .await?;
        let nodes: Vec<TraceNode> =
            nodes.rows.iter().map(|row| TraceNode { id: text(row.first()), kind: text(row.get(1)), name: text(row.get(2)), count: number(row.get(3)) as u32 }).collect();
        let edges = self
            .read("MATCH (a:Process {trace: $id})-[e]->(b) WHERE b.trace = $id RETURN a.id, b.id, type(e), e.count LIMIT 1000", params! { "id" => id })
            .await?;
        let edges =
            edges.rows.iter().map(|row| TraceEdge { from: text(row.first()), to: text(row.get(1)), kind: text(row.get(2)).to_lowercase(), count: number(row.get(3)) as u32 }).collect();
        Ok(TraceGraph { nodes, edges })
    }

    /// The records of `from..=to`: the first one at or after `from` is found by halving the
    /// stream's offsets (records are in time order), then pages are read until `to`.
    pub async fn window(&self, id: &str, from: u64, to: u64, kinds: &[String], limit: u32) -> Result<TraceWindow, RpcError> {
        validate_id(id)?;
        let topic = topic_of(id);
        let limit = if limit == 0 { 500 } else { limit.min(5000) } as usize;
        let (_, _, end) = self.graph.stream_fetch(&self.ig, &topic, 0, 1, 1 << 16).await?;
        let at_of = |records: &[(u64, Vec<u8>)]| records.first().and_then(|(offset, bytes)| serde_json::from_slice::<TraceRecord>(bytes).ok().map(|r| (*offset, r.at)));
        let (mut low, mut high) = (0u64, end);
        while low < high {
            let middle = low + (high - low) / 2;
            let (records, _, _) = self.graph.stream_fetch(&self.ig, &topic, middle, 1, 1 << 16).await?;
            match at_of(&records) {
                // Retention removed what came before: the first record kept is the next one.
                Some((offset, at)) if at < from => low = offset.max(middle) + 1,
                Some(_) => high = middle,
                None => low = middle + 1,
            }
        }
        let mut out = TraceWindow::default();
        let mut offset = low;
        'pages: while offset < end {
            let (records, next, _) = self.graph.stream_fetch(&self.ig, &topic, offset, 500, 1 << 20).await?;
            if records.is_empty() || next <= offset {
                break;
            }
            for (_, bytes) in records {
                let Ok(record) = serde_json::from_slice::<TraceRecord>(&bytes) else { continue };
                if record.at > to {
                    break 'pages;
                }
                if record.at < from || !(kinds.is_empty() || kinds.contains(&record.kind)) {
                    continue;
                }
                if out.records.len() == limit {
                    out.more = true;
                    break 'pages;
                }
                out.records.push(record);
            }
            offset = next;
        }
        Ok(out)
    }
}

/// The summary as a few short lines: what a model reads first.
fn render(summary: &TraceSummary) -> String {
    let t = &summary.trace;
    let mut out = String::new();
    let state = match (t.ended, t.exit_code) {
        (Some(_), Some(code)) => format!("exit {code}"),
        (Some(_), None) => "ended".into(),
        (None, _) => "still running".into(),
    };
    let _ = writeln!(out, "trace://{} · {} · {} · {}", t.id, t.label, duration(summary.to.saturating_sub(summary.from)), state);
    for metric in &summary.metrics {
        let shown = |value: f64| match metric.name.as_str() {
            "memory" => bytes(value as u64),
            "disk_write" => format!("{}/s", bytes(value as u64)),
            _ => format!("{value:.0}%"),
        };
        if metric.max <= 0.0 {
            continue;
        }
        let _ = writeln!(
            out,
            "{:<7} avg {} · p95 {} · peak {} at +{}",
            metric.name.replace("disk_write", "disk w"),
            shown(metric.avg),
            shown(metric.p95),
            shown(metric.max),
            duration(metric.max_at.saturating_sub(summary.from))
        );
    }
    if !summary.phases.is_empty() {
        let phases: Vec<String> = summary
            .phases
            .iter()
            .map(|p| format!("{} {:.0}% {}{}", duration(p.to - p.from), p.cpu, bytes(p.memory), p.busiest.first().map(|b| format!(" ({b})")).unwrap_or_default()))
            .collect();
        let _ = writeln!(out, "phases  {}", phases.join(" · "));
    }
    if !summary.processes.is_empty() {
        let procs: Vec<String> = summary.processes.iter().take(6).map(|p| if p.count > 1 { format!("{} ×{}", p.name, p.count) } else { p.name.clone() }).collect();
        let _ = writeln!(out, "ran     {}", procs.join(", "));
    }
    for (how, label) in [("wrote", "wrote"), ("read", "read"), ("connected", "hosts"), ("listened", "listens")] {
        let names: Vec<String> = summary.touched.iter().filter(|t| t.how == how).take(4).map(|t| if t.count > 1 && t.kind == "folder" { format!("{} ({})", t.name, t.count) } else { t.name.clone() }).collect();
        if !names.is_empty() {
            let _ = writeln!(out, "{label:<7} {}", names.join(", "));
        }
    }
    if summary.errors.is_empty() {
        let _ = writeln!(out, "errors  none seen");
    } else {
        let _ = writeln!(out, "errors  {}", summary.errors.iter().take(5).map(String::as_str).collect::<Vec<_>>().join(" | "));
    }
    for limit in &t.limits {
        let _ = writeln!(out, "note    {limit}");
    }
    out.trim_end().to_owned()
}

fn info_from(row: &[Value]) -> TraceInfo {
    TraceInfo {
        id: text(row.first()),
        label: text(row.get(1)),
        command: text(row.get(2)),
        cwd: text(row.get(3)),
        pid: number(row.get(4)) as u32,
        source: text(row.get(5)),
        run_id: row.get(6).and_then(Value::as_str).map(str::to_owned),
        asked_by: text(row.get(7)),
        started: number(row.get(8)) as u64,
        ended: row.get(9).filter(|v| !v.is_null()).map(|v| number(Some(v)) as u64),
        exit_code: row.get(10).filter(|v| !v.is_null()).map(|v| number(Some(v)) as i32),
        limits: row.get(11).and_then(Value::as_array).map(|list| list.iter().filter_map(Value::as_str).map(str::to_owned).collect()).unwrap_or_default(),
        records: number(row.get(12)) as u64,
    }
}

fn text(value: Option<&Value>) -> String {
    value.and_then(Value::as_str).unwrap_or("").to_owned()
}

/// A number however the result carries it (integers may arrive as strings).
fn number(value: Option<&Value>) -> f64 {
    match value {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(Value::String(s)) => s.parse().unwrap_or(0.0),
        _ => 0.0,
    }
}

fn topic_of(id: &str) -> String {
    format!("trace.{id}")
}

fn process_id(trace: &str, name: &str) -> String {
    format!("{trace}|process|{name}")
}

/// `t-` and 12 lowercase hex digits.
fn validate_id(id: &str) -> Result<(), RpcError> {
    let ok = id.len() == 14 && id.starts_with("t-") && id[2..].chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
    if ok { Ok(()) } else { Err(RpcError::invalid_params(format!("not a trace id: {id}"))) }
}

/// The folder a path is in (`/a/b/c.rs` -> `/a/b`); a name with no folder is its own.
fn folder_of(path: &str) -> String {
    match path.rfind('/') {
        Some(0) => "/".into(),
        Some(at) => path[..at].into(),
        None => path.into(),
    }
}

fn looks_wrong(line: &str) -> bool {
    let lower = line.to_lowercase();
    ["error", "fail", "panic", "fatal", "exception", "traceback", "warning", "denied", "segmentation fault"].iter().any(|word| lower.contains(word))
}

fn bytes(value: u64) -> String {
    let v = value as f64;
    if v >= 1e9 {
        format!("{:.1} GB", v / 1e9)
    } else if v >= 1e6 {
        format!("{:.0} MB", v / 1e6)
    } else if v >= 1e3 {
        format!("{:.0} KB", v / 1e3)
    } else {
        format!("{value} B")
    }
}

fn duration(ms: u64) -> String {
    let s = ms / 1000;
    if s >= 3600 {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    } else if s >= 60 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{s}s")
    }
}

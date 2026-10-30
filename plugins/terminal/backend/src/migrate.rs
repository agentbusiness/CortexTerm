//! The one-time import of what an earlier version kept in files: the SQLite table of Runs
//! (`runs.db`) and one output file per Run (`runs/<id>.txt`, `runs/<id>.zst`) in the plugin's data
//! folder, into the graph and the streams ([`crate::store`]), oldest first. Then the files are
//! deleted.
//!
//! It runs in the store's writer before anything new is sent, and can be interrupted at any
//! point: the graph merges (a second import writes the same nodes and edges), a shell's stream
//! gets only the events it does not hold yet (by event and Run id), and a Run's output stream
//! continues from the lines it already holds (line `n` is offset `n`). The files are deleted only
//! when the graph holds every Run, every shell stream its events and every output stream all its
//! lines; until then each start tries again. No progress is kept anywhere but in the graph.

use crate::store::{self, Batch, Line, ShellInfo, Store, Written};
use cc_protocol::RpcError;
use cc_protocol::contracts::memory::{StreamReadResult, methods as memory};
use cc_protocol::contracts::terminal::Run;
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// What an import did.
#[derive(Debug, Default, Clone)]
pub struct Report {
    pub runs: usize,
    pub shells: usize,
    pub events: usize,
    pub events_appended: usize,
    pub outputs: usize,
    pub lines: u64,
    pub lines_appended: u64,
    /// Output files without a Run row (deleted with the rest).
    pub orphans: usize,
    pub ms: u64,
}

fn legacy(dir: &Path) -> (PathBuf, PathBuf) {
    (dir.join("runs.db"), dir.join("runs"))
}

/// Import the earlier version's files, if there are any.
pub(crate) async fn run(store: &Store, written: &mut Written) -> Result<(), RpcError> {
    let Some(dir) = store.dir().map(Path::to_path_buf) else { return Ok(()) };
    let (db, outputs) = legacy(&dir);
    if !db.exists() && !outputs.exists() {
        return Ok(());
    }
    let report = import(store, written, &dir).await?;
    tracing::info!(
        runs = report.runs,
        shells = report.shells,
        events = report.events,
        events_appended = report.events_appended,
        outputs = report.outputs,
        lines = report.lines,
        lines_appended = report.lines_appended,
        orphans = report.orphans,
        ms = report.ms,
        "run store: imported runs.db and the output files into the graph; the files are deleted"
    );
    Ok(())
}

pub(crate) async fn import(store: &Store, written: &mut Written, dir: &Path) -> Result<Report, RpcError> {
    let clock = Instant::now();
    let (db, outputs) = legacy(dir);
    let mut runs = {
        let db = db.clone();
        tokio::task::spawn_blocking(move || read_runs(&db)).await.map_err(|e| RpcError::internal(e.to_string()))?.map_err(RpcError::internal)?
    };
    runs.sort_by(|a, b| (a.started, &a.id).cmp(&(b.started, &b.id)));
    let mut report = Report { runs: runs.len(), ..Report::default() };

    // The graph: each Run with its edges, the one before it in its shell, in batches.
    let mut first: HashMap<String, u64> = HashMap::new();
    for run in &runs {
        first.entry(run.term_id.clone()).or_insert(run.started);
    }
    report.shells = first.len();
    let mut previous: HashMap<String, String> = HashMap::new();
    let mut batch = Batch::default();
    for run in &runs {
        let info = ShellInfo { shell: String::new(), started_ms: first.get(&run.term_id).copied(), session: None };
        let before = previous.insert(run.term_id.clone(), run.id.clone());
        let one = store.run_batch(written, run, None, before, Some(&info), true);
        if batch.len() + one.len() > 4000 && !batch.is_empty() {
            store.put(&batch).await?;
            written.note(&batch);
            batch = Batch::default();
        }
        batch.extend(one);
    }
    store.put(&batch).await?;
    written.note(&batch);
    // Finished Runs get no other put; an unfinished one may still finish (its shell is alive).
    for run in runs.iter().filter(|run| run.ended.is_some()) {
        written.forget_run(&run.id);
    }

    // The shell streams: the events each one lacks, in order.
    let mut by_shell: HashMap<String, Vec<&Run>> = HashMap::new();
    for run in &runs {
        by_shell.entry(run.term_id.clone()).or_default().push(run);
    }
    let mut shells: Vec<(&String, &Vec<&Run>)> = by_shell.iter().collect();
    shells.sort_by(|a, b| a.0.cmp(b.0));
    for (term, list) in &shells {
        let topic = store::shell_topic(term);
        let have = events_in(store, &topic).await?;
        let mut records = Vec::new();
        for run in list.iter() {
            report.events += 1;
            if !have.contains(&("started".to_owned(), run.id.clone())) {
                // As it was when it started: the end and the counters came later.
                let start = Run { ended: None, exit_code: None, duration_ms: 0, lines: 0, bytes: 0, errors: 0, warnings: 0, ..(*run).clone() };
                records.push(store::event("started", &start));
            }
            if run.ended.is_some() {
                report.events += 1;
                if !have.contains(&("finished".to_owned(), run.id.clone())) {
                    records.push(store::event("finished", run));
                }
            }
        }
        report.events_appended += records.len();
        store.append(&topic, records, 3650).await?;
    }

    // The output streams: the lines each one lacks.
    let ids: HashSet<&str> = runs.iter().map(|r| r.id.as_str()).collect();
    let mut expected: Vec<(String, u64)> = Vec::new();
    for run in &runs {
        let Some(file) = output_file(&outputs, &run.id) else { continue };
        let lines = tokio::task::spawn_blocking(move || read_lines(&file)).await.map_err(|e| RpcError::internal(e.to_string()))?;
        if lines.is_empty() {
            continue;
        }
        report.outputs += 1;
        report.lines += lines.len() as u64;
        let stored = store.stored_lines(&run.id).await?;
        let missing: Vec<Value> = lines.iter().skip(stored as usize).map(Line::record).collect();
        report.lines_appended += missing.len() as u64;
        store.append(&store::output_topic(&run.id), missing, 30).await?;
        expected.push((run.id.clone(), lines.len() as u64));
    }
    if let Ok(entries) = std::fs::read_dir(&outputs) {
        report.orphans = entries
            .flatten()
            .filter(|e| e.path().file_stem().and_then(|s| s.to_str()).is_some_and(|id| !ids.contains(id)))
            .count();
    }

    // Check, then delete.
    let all: Vec<String> = runs.iter().map(|r| r.id.clone()).collect();
    let mut found = 0usize;
    for chunk in all.chunks(1000) {
        let rows = store.query("MATCH (r:CommandRun)-[:IN_SHELL]->(:Shell) WHERE r.key IN $ids RETURN count(r)", json!({"ids": chunk})).await?;
        found += rows.first().and_then(|r| r.first()).and_then(Value::as_u64).unwrap_or(0) as usize;
    }
    if found != runs.len() {
        return Err(RpcError::internal(format!("the graph holds {found} of the {} Runs", runs.len())));
    }
    for (term, list) in &shells {
        let have = events_in(store, &store::shell_topic(term)).await?;
        if let Some(run) = list.iter().find(|run| !have.contains(&("started".to_owned(), run.id.clone()))) {
            return Err(RpcError::internal(format!("shell.{term} lacks the start of {}", run.id)));
        }
    }
    for (id, lines) in &expected {
        let stored = store.stored_lines(id).await?;
        if stored < *lines {
            return Err(RpcError::internal(format!("the output of {id} holds {stored} of {lines} lines")));
        }
    }
    for path in [db.clone(), db.with_extension("db-wal"), db.with_extension("db-shm")] {
        if path.exists()
            && let Err(error) = std::fs::remove_file(&path)
        {
            tracing::warn!("run store: cannot delete {}: {error}", path.display());
        }
    }
    if outputs.exists()
        && let Err(error) = std::fs::remove_dir_all(&outputs)
    {
        tracing::warn!("run store: cannot delete {}: {error}", outputs.display());
    }
    report.ms = clock.elapsed().as_millis() as u64;
    Ok(report)
}

/// The (event, run id) pairs a shell stream holds.
async fn events_in(store: &Store, topic: &str) -> Result<HashSet<(String, String)>, RpcError> {
    let mut have = HashSet::new();
    let mut offset = 0u64;
    loop {
        let page: StreamReadResult = store.call(memory::STREAM_READ, json!({"topic": topic, "from_offset": offset, "limit": 5000})).await?;
        for record in &page.records {
            let field = |k: &str| record.value.get(k).and_then(Value::as_str).unwrap_or("").to_owned();
            have.insert((field("event"), field("id")));
        }
        if page.end || page.records.is_empty() {
            break;
        }
        offset = page.next_offset;
    }
    Ok(have)
}

fn read_runs(db: &Path) -> Result<Vec<Run>, String> {
    if !db.exists() {
        return Ok(Vec::new());
    }
    let conn = rusqlite::Connection::open(db).map_err(|e| format!("{}: {e}", db.display()))?;
    let _ = conn.busy_timeout(std::time::Duration::from_secs(2));
    let has_table: bool = conn
        .query_row("SELECT count(*) FROM sqlite_master WHERE type = 'table' AND name = 'runs'", [], |row| row.get::<_, i64>(0))
        .map(|n| n > 0)
        .map_err(|e| e.to_string())?;
    if !has_table {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare(
            "SELECT id, term_id, command, cwd, started, ended, exit_code, duration_ms, lines, bytes, format, errors, warnings, author, fullscreen, usual_ms \
             FROM runs ORDER BY started, id",
        )
        .map_err(|e| e.to_string())?;
    let u = |row: &rusqlite::Row, i: usize| row.get::<_, Option<i64>>(i).map(|v| v.unwrap_or(0).max(0) as u64);
    let rows = statement
        .query_map([], |row| {
            Ok(Run {
                id: row.get(0)?,
                term_id: row.get(1)?,
                command: row.get(2)?,
                cwd: row.get(3)?,
                started: u(row, 4)?,
                ended: row.get::<_, Option<i64>>(5)?.map(|v| v.max(0) as u64),
                exit_code: row.get(6)?,
                duration_ms: u(row, 7)?,
                lines: u(row, 8)?,
                bytes: u(row, 9)?,
                format: row.get::<_, Option<String>>(10)?.unwrap_or_else(|| "raw".into()),
                errors: u(row, 11)?,
                warnings: u(row, 12)?,
                author: row.get::<_, Option<String>>(13)?.unwrap_or_else(|| "user".into()),
                fullscreen: row.get::<_, Option<i64>>(14)?.unwrap_or(0) != 0,
                usual_ms: u(row, 15)?,
            })
        })
        .map_err(|e| e.to_string())?;
    Ok(rows.flatten().filter(|run| store::valid_id(&run.id)).collect())
}

fn output_file(outputs: &Path, id: &str) -> Option<PathBuf> {
    if !store::valid_id(id) {
        return None;
    }
    [outputs.join(format!("{id}.zst")), outputs.join(format!("{id}.txt"))].into_iter().find(|p| p.exists())
}

/// An output file's lines. A record is `<arrival ms>\t<level>\t<text>`, or, for a line that had
/// colour or style codes, `<arrival ms>\t<level>;<text bytes>\t<text><ansi>`.
fn read_lines(file: &Path) -> Vec<Line> {
    let Ok(handle) = std::fs::File::open(file) else { return Vec::new() };
    let reader: Box<dyn Read> = if file.extension().is_some_and(|e| e == "zst") {
        match zstd::stream::read::Decoder::new(handle) {
            Ok(decoder) => Box::new(decoder),
            Err(_) => return Vec::new(),
        }
    } else {
        Box::new(handle)
    };
    let mut lines = Vec::new();
    let mut reader = BufReader::new(reader);
    let mut raw = Vec::new();
    loop {
        raw.clear();
        // A file cut short (the plugin stopped while writing) keeps its whole lines only.
        match reader.read_until(b'\n', &mut raw) {
            Ok(n) if n > 0 && raw.last() == Some(&b'\n') => raw.pop(),
            _ => break,
        };
        let raw = String::from_utf8_lossy(&raw);
        let mut parts = raw.splitn(3, '\t');
        let at = parts.next().and_then(|v| v.parse().ok()).unwrap_or(0);
        let level = parts.next().unwrap_or("");
        let rest = parts.next().unwrap_or("");
        let (level, text, ansi) = match level.split_once(';').and_then(|(level, len)| Some((level, len.parse::<usize>().ok()?))) {
            Some((level, len)) if rest.is_char_boundary(len.min(rest.len())) => {
                let (text, ansi) = rest.split_at(len.min(rest.len()));
                (level, text, ansi)
            }
            _ => (level, rest, ""),
        };
        lines.push(Line { at, level: level.to_owned(), text: text.to_owned(), ansi: ansi.to_owned() });
    }
    lines
}

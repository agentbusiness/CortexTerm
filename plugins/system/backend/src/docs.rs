//! Downloaded lists kept whole as documents in the graph: `(:Feed {key: name, url, fetched_ms,
//! bytes, encoding, parts, body})-[:ON]->(:Machine)`. A list larger than one part (1 MB of text)
//! is split at line ends into `(:FeedPart {key: name#n, n, fetched_ms, body})-[:OF]->(:Feed)`; a
//! binary one (the gzip'd IP-to-network table) is kept as base64. A copy read once stays in RAM
//! (the big IP table is not kept: its parsed tables are).

use crate::graph::{self, Batch, Props, r};
use base64::Engine;
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Characters of body per node.
const PART: usize = 1 << 20;
/// Lists bigger than this are read when asked, not kept in RAM.
const KEEP: usize = 4 << 20;

#[derive(Clone)]
pub struct Doc {
    pub bytes: Arc<Vec<u8>>,
}

/// name -> when the stored copy was fetched (0: none stored).
static INDEX: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);
static CACHE: Mutex<Option<HashMap<String, Doc>>> = Mutex::new(None);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Which lists the graph holds and their age (once, at start).
pub async fn load_index() -> Result<usize, String> {
    let rows = graph::query("MATCH (f:Feed) WHERE f.state IS NULL OR f.state <> 'gone' RETURN f.key, f.fetched_ms", json!({})).await?;
    let index: HashMap<String, u64> = rows.iter().map(|row| (graph::text(&row[0]), graph::number(&row[1]))).collect();
    let count = index.len();
    *lock(&INDEX) = Some(index);
    Ok(count)
}

/// When the stored copy was fetched (None: there is none, or memory is not loaded yet).
pub fn fetched(name: &str) -> Option<u64> {
    lock(&INDEX).as_ref()?.get(name).copied().filter(|at| *at > 0)
}

/// The stored copy (async).
pub async fn get(name: &str) -> Option<Doc> {
    if let Some(doc) = lock(&CACHE).as_ref().and_then(|cache| cache.get(name).cloned()) {
        return Some(doc);
    }
    fetched(name)?;
    let rows = graph::query("MATCH (f:Feed {key: $k}) RETURN f.fetched_ms, f.encoding, f.parts, f.body", json!({"k": name})).await.ok()?;
    let row = rows.first()?;
    let at = graph::number(&row[0]);
    let encoding = graph::text(&row[1]);
    let parts = graph::number(&row[2]);
    let mut body = String::new();
    if parts == 0 {
        body = graph::text(&row[3]);
    } else {
        for n in 0..parts {
            let rows = graph::query(
                "MATCH (p:FeedPart {key: $k}) WHERE p.fetched_ms = $at RETURN p.body",
                json!({"k": format!("{name}#{n}"), "at": at}),
            )
            .await
            .ok()?;
            body.push_str(&graph::text(&rows.first()?[0]));
        }
    }
    let bytes = if encoding == "base64" { base64::engine::general_purpose::STANDARD.decode(body.as_bytes()).ok()? } else { body.into_bytes() };
    let doc = Doc { bytes: Arc::new(bytes) };
    if doc.bytes.len() <= KEEP {
        lock(&CACHE).get_or_insert_with(HashMap::new).insert(name.to_owned(), doc.clone());
    }
    Some(doc)
}

/// [`get`] from a blocking thread.
pub fn get_blocking(name: &str) -> Option<Doc> {
    graph::block(get(name)).flatten()
}

/// Keep a fresh copy (in RAM now, in the graph through the writer).
pub fn put(name: &str, url: &str, bytes: Vec<u8>, fetched_ms: u64) {
    let size = bytes.len();
    if let Some(batches) = batches(name, url, &bytes, fetched_ms) {
        for batch in batches {
            graph::put(batch);
        }
        lock(&INDEX).get_or_insert_with(HashMap::new).insert(name.to_owned(), fetched_ms);
    }
    let mut cache = lock(&CACHE);
    let cache = cache.get_or_insert_with(HashMap::new);
    if size <= KEEP {
        cache.insert(name.to_owned(), Doc { bytes: Arc::new(bytes) });
    } else {
        cache.remove(name);
    }
}

/// The nodes a list is kept as, one put per part (None before memory answered).
pub fn batches(name: &str, url: &str, bytes: &[u8], fetched_ms: u64) -> Option<Vec<Batch>> {
    let machine = graph::machine()?;
    let (encoding, body) = match std::str::from_utf8(bytes) {
        Ok(text) => ("text", text.to_owned()),
        Err(_) => ("base64", base64::engine::general_purpose::STANDARD.encode(bytes)),
    };
    let pieces = split(&body);
    let at_ms = Some(fetched_ms.min(crate::util::now_ms()));
    let mut batch = Batch { at_ms, ..Default::default() };
    let unit = batch.unit();
    let feed = unit.node("Feed", name);
    feed.p("url", url).p("fetched_ms", fetched_ms).p("bytes", bytes.len() as u64).p("encoding", encoding);
    if pieces.len() <= 1 {
        feed.p("parts", 0).p("body", body);
    } else {
        feed.p("parts", pieces.len() as u64).p("body", serde_json::Value::Null);
    }
    unit.edge(r("Feed", name), "ON", machine);
    let mut out = vec![batch];
    if pieces.len() > 1 {
        for (n, piece) in pieces.iter().enumerate() {
            let key = format!("{name}#{n}");
            let mut batch = Batch { at_ms, ..Default::default() };
            let unit = batch.unit();
            unit.node("FeedPart", key.clone()).p("n", n as u64).p("fetched_ms", fetched_ms).p("body", piece.as_str());
            unit.edge(r("FeedPart", key), "OF", r("Feed", name));
            out.push(batch);
        }
    }
    Some(out)
}

/// At most [`PART`] bytes each, cut after a line end when there is one.
fn split(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = body;
    while rest.len() > PART {
        let mut end = PART;
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if let Some(newline) = rest[..end].rfind('\n') {
            end = newline + 1;
        }
        out.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    out.push(rest.to_owned());
    out
}

//! Downloaded lists kept whole as cache files in the data folder (`feeds/<name>`; the file's
//! modification time is when it was fetched), never in the graph: they are megabytes each and can
//! be fetched again. A copy read once stays in RAM (the big IP table is not kept: its parsed
//! tables are).

use crate::graph::{self, r};
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, UNIX_EPOCH};

/// Lists bigger than this are read when asked, not kept in RAM.
const KEEP: usize = 4 << 20;

#[derive(Clone)]
pub struct Doc {
    pub bytes: Arc<Vec<u8>>,
}

/// name -> when the stored copy was fetched.
static INDEX: Mutex<Option<HashMap<String, u64>>> = Mutex::new(None);
static CACHE: Mutex<Option<HashMap<String, Doc>>> = Mutex::new(None);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn dir() -> PathBuf {
    crate::util::data_dir().join("feeds")
}

/// Which lists are on disk and their age (once, at start). Lists earlier versions kept in the
/// graph (`Feed`, `FeedPart`) are retired.
pub async fn load_index() -> Result<usize, String> {
    let mut index = HashMap::new();
    for entry in std::fs::read_dir(dir()).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.ends_with(".tmp") {
            continue;
        }
        let fetched = entry.metadata().and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64);
        if let Some(fetched) = fetched {
            index.insert(name, fetched);
        }
    }
    let count = index.len();
    *lock(&INDEX) = Some(index);
    for label in ["Feed", "FeedPart"] {
        let rows = graph::query_all(&format!("MATCH (f:{label}) WHERE f.state IS NULL OR f.state <> 'gone' RETURN f.key"), json!({})).await?;
        if !rows.is_empty() {
            graph::retire(rows.iter().map(|row| r(label, graph::text(&row[0]))).collect(), "downloaded lists are cache files now");
        }
    }
    Ok(count)
}

/// When the stored copy was fetched (None: there is none, or the index is not loaded yet).
pub fn fetched(name: &str) -> Option<u64> {
    lock(&INDEX).as_ref()?.get(name).copied()
}

/// The stored copy (async).
pub async fn get(name: &str) -> Option<Doc> {
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || get_blocking(&name)).await.ok().flatten()
}

/// [`get`] from a blocking thread.
pub fn get_blocking(name: &str) -> Option<Doc> {
    if let Some(doc) = lock(&CACHE).as_ref().and_then(|cache| cache.get(name).cloned()) {
        return Some(doc);
    }
    fetched(name)?;
    let doc = Doc { bytes: Arc::new(std::fs::read(dir().join(name)).ok()?) };
    if doc.bytes.len() <= KEEP {
        lock(&CACHE).get_or_insert_with(HashMap::new).insert(name.to_owned(), doc.clone());
    }
    Some(doc)
}

/// Keep a fresh copy, in RAM and on disk (written whole, then renamed into place).
pub fn put(name: &str, bytes: Vec<u8>, fetched_ms: u64) {
    let (dir, size) = (dir(), bytes.len());
    let tmp = dir.join(format!("{name}.tmp"));
    let written = std::fs::create_dir_all(&dir)
        .and_then(|_| std::fs::write(&tmp, &bytes))
        .and_then(|_| std::fs::File::options().write(true).open(&tmp)?.set_modified(UNIX_EPOCH + Duration::from_millis(fetched_ms)))
        .and_then(|_| std::fs::rename(&tmp, dir.join(name)));
    match written {
        Ok(()) => {
            lock(&INDEX).get_or_insert_with(HashMap::new).insert(name.to_owned(), fetched_ms);
        }
        Err(error) => tracing::warn!("feed {name}: could not be kept on disk: {error}"),
    }
    let mut cache = lock(&CACHE);
    let cache = cache.get_or_insert_with(HashMap::new);
    if size <= KEEP {
        cache.insert(name.to_owned(), Doc { bytes: Arc::new(bytes) });
    } else {
        cache.remove(name);
    }
}

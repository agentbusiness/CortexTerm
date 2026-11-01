//! What the root-only commands the sweep offers saw (the full login-items database, an hour of
//! eslogger). The person runs the command in a terminal; it writes into this user's temporary
//! folder (`$TMPDIR/cortexterm-deep`), and the next sweep moves what it says into the graph and
//! deletes the file:
//!
//! - the login-items database (`sfltool dumpbtm`): each item as `(:StartItem {key: btm:…, source:
//!   btm, label, identifier, kind, disposition, program, url, team, developer})-[:ON]->(:Machine)`
//!   (`-[:STARTS]->(:Binary)` when it names a program), the dump as `(:MacSetting {key: btm_dump,
//!   value*, checked_ms, items})`;
//! - eslogger: what it flagged in the stream `eslogger` (`{capture, severity, text}`), the
//!   recording as `(:MacSetting {key: eslogger, value*, checked_ms, events})`.
//!
//! Blocking: called from the sweep's checks.

use crate::graph::{self, Batch, Props, r};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

/// The fields of a BTM record kept, with the property each is kept as.
const BTM_FIELDS: &[(&str, &str)] = &[
    ("Name", "label"),
    ("Identifier", "identifier"),
    ("Type", "kind"),
    ("Disposition", "disposition"),
    ("Executable Path", "program"),
    ("URL", "url"),
    ("Team Identifier", "team"),
    ("Developer Name", "developer"),
];

/// Where the commands write: this user's own temporary folder (not `/tmp`, which anyone can
/// write to).
pub fn dir() -> PathBuf {
    std::env::temp_dir().join("cortexterm-deep")
}

/// A command's output file when it exists and nothing wrote to it for 5 minutes (the command is
/// done), with when it was last written (Unix ms).
fn finished(name: &str) -> Option<(PathBuf, u64)> {
    let path = dir().join(name);
    let modified = std::fs::metadata(&path).ok()?.modified().ok()?;
    if modified.elapsed().unwrap_or_default() < Duration::from_secs(300) {
        return None;
    }
    let at = modified.duration_since(std::time::UNIX_EPOCH).ok()?.as_millis() as u64;
    Some((path, at))
}

fn setting_unit(batch: &mut Batch, key: &str, value: String, at: u64, count: (&str, u64)) -> Option<()> {
    let machine = graph::machine()?;
    let unit = batch.unit();
    unit.node("MacSetting", key).t("value", value).p("checked_ms", at).p(count.0, count.1);
    unit.edge(r("MacSetting", key), "OF", machine);
    Some(())
}

/// When a stored capture was made and how big it was.
fn setting(key: &str, count: &str) -> Option<(u64, u64)> {
    let cypher = format!("MATCH (s:MacSetting {{key: $k}}) RETURN s.checked_ms, s.{count}");
    let rows = graph::block(graph::query(&cypher, json!({"k": key})))?.ok()?;
    let row = rows.first()?;
    Some((graph::number(&row[0]), graph::number(&row[1]))).filter(|(at, _)| *at > 0)
}

/// Parse `sfltool dumpbtm`'s text into records.
fn parse_btm(text: &str) -> Vec<BTreeMap<String, String>> {
    let mut records: Vec<BTreeMap<String, String>> = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') && trimmed.ends_with(':') {
            records.push(BTreeMap::new());
            continue;
        }
        if let (Some(record), Some((key, value))) = (records.last_mut(), trimmed.split_once(": ")) {
            record.entry(key.trim().to_owned()).or_insert_with(|| value.trim().to_owned());
        }
    }
    records
}

fn btm_key(record: &BTreeMap<String, String>, index: usize) -> String {
    let get = |k: &str| record.get(k).map(String::as_str).filter(|v| !v.is_empty() && *v != "(null)").unwrap_or("");
    let id = [get("Identifier"), get("URL"), get("Executable Path"), get("Name")].into_iter().find(|v| !v.is_empty()).unwrap_or("");
    if id.is_empty() { format!("btm:#{index}") } else { format!("btm:{id}") }
}

/// The login-items database as last dumped: when, and its records. A new dump is moved into the
/// graph first. None when there is none (or memory is not reachable).
pub fn btm() -> Option<(u64, Vec<BTreeMap<String, String>>)> {
    if !graph::ready() {
        return None;
    }
    if let Some((path, at)) = finished("btm.txt")
        && let Ok(text) = std::fs::read_to_string(&path)
    {
        let records = parse_btm(&text);
        let old: Vec<String> = graph::block(graph::query_all(
            "MATCH (s:StartItem) WHERE s.source = 'btm' AND (s.state IS NULL OR s.state <> 'gone') RETURN s.key ORDER BY s.key",
            json!({}),
        ))
        .and_then(Result::ok)
        .unwrap_or_default()
        .iter()
        .map(|row| graph::text(&row[0]))
        .collect();
        let mut batch = Batch { at_ms: Some(at), ..Default::default() };
        let mut keys = std::collections::HashSet::new();
        if let Some(machine) = graph::machine() {
            for (index, record) in records.iter().enumerate() {
                let key = btm_key(record, index);
                keys.insert(key.clone());
                let unit = batch.unit();
                let node = unit.node("StartItem", key.clone());
                // `name` is the label's name before 0.1.21.
                node.p("source", "btm").p("name", serde_json::Value::Null);
                for (field, prop) in BTM_FIELDS {
                    node.p(prop, record.get(*field).cloned().filter(|v| v != "(null)").unwrap_or_default());
                }
                unit.edge(r("StartItem", key.clone()), "ON", machine.clone());
                if let Some(program) = record.get("Executable Path").filter(|p| p.starts_with('/')) {
                    unit.node("Binary", program.clone());
                    unit.edge(r("StartItem", key), "STARTS", r("Binary", program.clone()));
                }
            }
        }
        setting_unit(&mut batch, "btm_dump", format!("{} items", records.len()), at, ("items", records.len() as u64));
        graph::put(batch);
        let gone: Vec<_> = old.into_iter().filter(|k| !keys.contains(k)).map(|k| r("StartItem", k)).collect();
        if !gone.is_empty() {
            graph::retire(gone, "not in the login-items database any more");
        }
        let _ = std::fs::remove_file(&path);
        return Some((at, records));
    }
    let (at, _) = setting("btm_dump", "items")?;
    let props: Vec<&str> = BTM_FIELDS.iter().map(|(_, p)| *p).collect();
    let cypher = format!(
        "MATCH (s:StartItem) WHERE s.source = 'btm' AND (s.state IS NULL OR s.state <> 'gone') RETURN {} ORDER BY s.key",
        props.iter().map(|p| format!("s.{p}")).collect::<Vec<_>>().join(", ")
    );
    let rows = graph::block(graph::query_all(&cypher, json!({})))?.ok()?;
    let records = rows
        .iter()
        .map(|row| BTM_FIELDS.iter().zip(row).map(|((field, _), value)| ((*field).to_owned(), graph::text(value))).collect())
        .collect();
    Some((at, records))
}

/// An eslogger recording: when it was made, how many events, and what was flagged
/// (severity, text). A new recording is read with `flag` and moved into the graph first.
pub fn eslogger(flag: impl Fn(&std::path::Path) -> (usize, Vec<(String, String)>)) -> Option<(u64, u64, Vec<(String, String)>)> {
    if !graph::ready() {
        return None;
    }
    if let Some((path, at)) = finished("eslogger.jsonl") {
        let (events, notes) = flag(&path);
        let mut batch = Batch::new();
        setting_unit(&mut batch, "eslogger", format!("{events} events"), at, ("events", events as u64));
        graph::put(batch);
        let records = notes.iter().map(|(severity, text)| json!({"capture": at, "severity": severity, "text": text})).collect();
        graph::append("eslogger", records, 8);
        let _ = std::fs::remove_file(&path);
        return Some((at, events as u64, notes));
    }
    let (at, events) = setting("eslogger", "events")?;
    let notes = graph::block(graph::stream_read("eslogger", at.saturating_sub(1)))?
        .ok()?
        .into_iter()
        .filter(|entry| entry.value["capture"].as_u64() == Some(at))
        .map(|entry| (graph::text(&entry.value["severity"]), graph::text(&entry.value["text"])))
        .collect();
    Some((at, events, notes))
}

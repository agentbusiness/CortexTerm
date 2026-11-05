//! The alert store: each watcher offers a candidate under a key (kind + subject); the store fires it
//! at most once an hour per key, honours snooze, dismiss and ignored kinds, and keeps the alerts
//! in the graph:
//!
//! - `(:Alert {key: id, kind, severity, text, at, subject, pid, port, path, actions, dismissed,
//!   quiet_until})-[:OF]->(:AlertKind {key: kind, ignored*})-[:ON]->(:Machine)`, and
//!   `-[:ABOUT]->` what it is about when that is a node (a start item, an advisory);
//! - the stream `alerts`: every alert, in order, as it fired.
//!
//! The last week is loaded once at start; until then candidates wait in RAM and are offered again.

use crate::graph::{self, Batch, Props, r};
use crate::util::now_ms;
use cc_protocol::contracts::memory::GraphRef;
use cc_protocol::contracts::system::{Alert, AlertList};
use serde_json::{Value, json};
use std::collections::HashMap;

const HOUR: u64 = 3_600_000;
const WEEK: u64 = 7 * 24 * HOUR;
/// The `alerts` stream keeps a year.
const STREAM_DAYS: u32 = 365;

/// What a watcher wants to say; `key` is the kind and subject it is deduplicated on.
pub struct Candidate {
    pub key: String,
    pub alert: Alert,
}

#[derive(Debug, Clone)]
struct Stored {
    alert: Alert,
    key: String,
}

#[derive(Default)]
pub struct AlertStore {
    alerts: Vec<Stored>,
    /// key -> when it last fired.
    last: HashMap<String, u64>,
    /// key -> quiet until.
    quiet: HashMap<String, u64>,
    ignored_kinds: Vec<String>,
    counter: u64,
    /// Loaded from the graph; before that, candidates wait in `early`.
    loaded: bool,
    early: Vec<Candidate>,
}

impl AlertStore {
    /// The last week of alerts, the quiet keys and the ignored kinds.
    pub async fn load() -> Result<AlertStore, String> {
        let mut store = AlertStore { loaded: true, ..Default::default() };
        let rows = graph::query_all(
            "MATCH (a:Alert) WHERE a.at >= $since AND a.ended_ms IS NULL RETURN a.key, a.kind, a.severity, a.text, a.at, a.subject, a.pid, a.port, a.path, a.actions, a.dismissed, a.quiet_until ORDER BY a.at",
            json!({"since": now_ms().saturating_sub(WEEK)}),
        )
        .await?;
        let now = now_ms();
        for row in rows {
            let alert = Alert {
                id: graph::text(&row[0]),
                kind: graph::text(&row[1]),
                severity: graph::text(&row[2]),
                text: graph::text(&row[3]),
                at: graph::number(&row[4]),
                pid: row[6].as_u64().map(|p| p as u32),
                port: row[7].as_u64().map(|p| p as u16),
                path: row[8].as_str().map(str::to_owned),
                actions: graph::texts(&row[9]),
                dismissed: row[10].as_bool().unwrap_or(false),
            };
            let key = graph::text(&row[5]);
            store.last.insert(key.clone(), alert.at);
            let until = graph::number(&row[11]);
            if until > now {
                let quiet = store.quiet.entry(key.clone()).or_default();
                *quiet = (*quiet).max(until);
            }
            store.alerts.push(Stored { alert, key });
        }
        let rows = graph::query("MATCH (k:AlertKind) WHERE k.ignored = true RETURN k.key", json!({})).await?;
        store.ignored_kinds = rows.iter().map(|row| graph::text(&row[0])).collect();
        Ok(store)
    }

    /// Candidates offered before the store was loaded (to offer again now).
    pub fn take_early(&mut self) -> Vec<Candidate> {
        std::mem::take(&mut self.early)
    }

    /// Bring a loaded store in, keeping candidates that arrived meanwhile.
    pub fn replace(&mut self, mut loaded: AlertStore) {
        loaded.early = std::mem::take(&mut self.early);
        loaded.counter = self.counter;
        *self = loaded;
    }

    fn trim(&mut self) {
        let now = now_ms();
        self.alerts.retain(|s| now.saturating_sub(s.alert.at) < WEEK);
        if self.alerts.len() > 300 {
            let excess = self.alerts.len() - 300;
            self.alerts.drain(..excess);
        }
        self.last.retain(|_, at| now.saturating_sub(*at) < WEEK);
        self.quiet.retain(|_, until| *until > now);
    }

    /// Fire the candidate unless its key fired within the hour, is quiet, or its kind is ignored.
    /// `about` is the node it is about, when there is one.
    pub fn offer(&mut self, candidate: Candidate, about: Option<GraphRef>) -> Option<Alert> {
        if !self.loaded {
            if self.early.len() < 200 {
                self.early.push(candidate);
            }
            return None;
        }
        let now = now_ms();
        let Candidate { key, mut alert } = candidate;
        if self.ignored_kinds.contains(&alert.kind)
            || self.last.get(&key).is_some_and(|at| now.saturating_sub(*at) < HOUR)
            || self.quiet.get(&key).is_some_and(|until| *until > now)
        {
            return None;
        }
        self.counter += 1;
        alert.id = format!("{}-{now:x}-{}", alert.kind, self.counter);
        alert.at = now;
        alert.dismissed = false;
        self.last.insert(key.clone(), now);
        self.write(&alert, &key, None, about);
        graph::append("alerts", vec![json!({"id": alert.id, "kind": alert.kind, "severity": alert.severity, "text": alert.text, "subject": key, "at": alert.at, "pid": alert.pid, "port": alert.port, "path": alert.path})], STREAM_DAYS);
        self.alerts.push(Stored { alert: alert.clone(), key });
        self.trim();
        Some(alert)
    }

    /// What they said is no longer true (an update fixed it): the open alerts of `kind` whose key
    /// is not in `still` close.
    pub fn settle(&mut self, kind: &str, still: &std::collections::BTreeSet<String>) {
        for stored in self.alerts.iter_mut().filter(|s| s.alert.kind == kind && !s.alert.dismissed && !still.contains(&s.key)) {
            stored.alert.dismissed = true;
            let mut batch = Batch::new();
            batch.unit().node("Alert", stored.alert.id.clone()).p("dismissed", true);
            graph::put(batch);
        }
    }

    /// Remove every alert and forget when each fired, so what is still true fires again.
    pub fn clear(&mut self) {
        let gone: Vec<GraphRef> = self.alerts.drain(..).map(|stored| graph::r("Alert", stored.alert.id)).collect();
        if !gone.is_empty() {
            graph::retire(gone, "cleared");
        }
        self.last.clear();
    }

    /// The alert's node (with its kind's) as it is now.
    fn write(&self, alert: &Alert, key: &str, quiet_until: Option<u64>, about: Option<GraphRef>) {
        let Some(machine) = graph::machine() else { return };
        let mut batch = Batch::new();
        let unit = batch.unit();
        unit.node("AlertKind", alert.kind.clone());
        unit.edge(r("AlertKind", alert.kind.clone()), "ON", machine);
        let node = unit.node("Alert", alert.id.clone());
        node.p("kind", alert.kind.clone())
            .p("severity", alert.severity.clone())
            .p("text", alert.text.clone())
            .p("at", alert.at)
            .p("subject", key)
            .po("pid", alert.pid)
            .po("port", alert.port)
            .po("path", alert.path.clone())
            .pl("actions", alert.actions.clone())
            .p("dismissed", alert.dismissed)
            .po("quiet_until", quiet_until);
        unit.edge(r("Alert", alert.id.clone()), "OF", r("AlertKind", alert.kind.clone()));
        if let Some(about) = about {
            unit.edge(r("Alert", alert.id.clone()), "ABOUT", about);
        }
        graph::put(batch);
    }

    /// Newest first.
    pub fn list(&self) -> AlertList {
        AlertList { alerts: self.alerts.iter().rev().map(|s| s.alert.clone()).collect() }
    }

    /// `dismiss` (quiet for a day), `snooze` (quiet for an hour) or `ignore_kind` (never again).
    pub fn act(&mut self, id: &str, action: &str) -> Result<(), String> {
        let now = now_ms();
        let index = self.alerts.iter().position(|s| s.alert.id == id).ok_or_else(|| format!("no alert {id}"))?;
        let (key, kind) = (self.alerts[index].key.clone(), self.alerts[index].alert.kind.clone());
        match action {
            "dismiss" | "snooze" => {
                let until = now + if action == "dismiss" { 24 * HOUR } else { HOUR };
                self.quiet.insert(key.clone(), until);
                self.alerts[index].alert.dismissed = true;
                self.write(&self.alerts[index].alert, &key, Some(until), None);
            }
            "ignore_kind" => {
                if !self.ignored_kinds.contains(&kind) {
                    self.ignored_kinds.push(kind.clone());
                }
                if let Some(machine) = graph::machine() {
                    let mut batch = Batch::new();
                    let unit = batch.unit();
                    unit.node("AlertKind", kind.clone()).t("ignored", true);
                    unit.edge(r("AlertKind", kind.clone()), "ON", machine);
                    graph::put(batch);
                }
                for stored in self.alerts.iter_mut().filter(|s| s.alert.kind == kind && !s.alert.dismissed) {
                    stored.alert.dismissed = true;
                    let mut batch = Batch::new();
                    batch.unit().node("Alert", stored.alert.id.clone()).p("dismissed", true);
                    graph::put(batch);
                }
            }
            other => return Err(format!("unknown action {other:?}; use dismiss, snooze or ignore_kind")),
        }
        self.trim();
        Ok(())
    }
}

/// An alert's record for the `alerts` stream, from the old file's form (`migrate`).
pub fn stream_record(alert: &Alert, key: &str) -> Value {
    json!({"id": alert.id, "kind": alert.kind, "severity": alert.severity, "text": alert.text, "subject": key, "at": alert.at, "pid": alert.pid, "port": alert.port, "path": alert.path})
}

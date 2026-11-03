//! Local security incidents. Collection is facts; correlation and severity are code; the model
//! can gather bounded read-only evidence and explain it. Nothing in this module runs a shell.
//! State is app-local in IronGraph. A missing collector is never an all-clear:
//!
//! - setting `protection.config`: the [`ProtectionConfig`];
//! - `(:ProtectionIncident {key: id, incident_key, first_at, last_at, title, severity, state,
//!   revision, omitted_observations})-[:ON]->(:Machine)`, `-[:INVOLVES]->(:Binary)` for each
//!   executable it observed, `-[:ABOUT]->` what a sweep group's findings are about;
//! - `(:ProtectionException {key: id, incident_key, created_at, expires_at, reason,
//!   observation_keys, max_severity})-[:FOR]->(:ProtectionIncident)`, retired when it ends;
//! - stream `protection.observations`: `{incident, observation}` each time an observation enters
//!   an incident or changes (14 days); the latest of each counts;
//! - stream `protection.investigations`: `{incident, investigation}` on each change (14 days).

use crate::graph::{self, Props};
use crate::procs::Snapshot;
use crate::util::now_ms;
use cc_protocol::contracts::memory::GraphRef;
use cc_protocol::contracts::system::*;
use regex::Regex;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const DAY: u64 = 86_400_000;
const RETENTION: u64 = 14 * DAY;
const MAX_INCIDENTS: usize = 100;
const MAX_OBSERVATIONS: usize = 64;
const MAX_QUEUE: usize = 2048;
const CONFIG: &str = "protection.config";
const OBSERVATIONS: &str = "protection.observations";
const INVESTIGATIONS: &str = "protection.investigations";
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicU64 = AtomicU64::new(0);
static QUEUE: Mutex<VecDeque<SecurityObservation>> = Mutex::new(VecDeque::new());
static HEALTH: Mutex<BTreeMap<String, ProtectionSensor>> = Mutex::new(BTreeMap::new());

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// The incident subject of a sweep finding group: one incident per group, which the window finds
/// by the group's name.
pub fn group_subject(group: &str) -> String {
    format!("group:{group}")
}

pub fn digest(text: &str) -> String {
    Sha256::digest(text.as_bytes())[..16]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn observation_key(e: &SecurityObservation) -> String {
    digest(&format!(
        "{}|{}|{}|{}|{:?}|{:?}|{:?}",
        e.source, e.subject, e.kind, e.rule, e.path, e.remote, e.port
    ))
}

/// Remove terminal controls, common secret forms and URL credentials/query strings before
/// observations enter memory or inference. Collectors must not pass raw args/env/payloads here.
pub fn scrub(text: &str, limit: usize) -> String {
    static SECRETS: OnceLock<Regex> = OnceLock::new();
    static URLS: OnceLock<Regex> = OnceLock::new();
    let clean: String = text
        .chars()
        .filter(|c| {
            !c.is_control() && !matches!(*c, '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        })
        .take(limit.saturating_mul(4))
        .collect();
    let re = SECRETS.get_or_init(|| Regex::new(r#"(?i)(?:\b(?:bearer|basic)\s+\S+|\b(?:[A-Z_]*(?:token|password|passwd|secret|api[_-]?key|credential)[A-Z_]*|authorization)\s*[=:]\s*(?:"[^"]*"|'[^']*'|[^\s,;]+)|\b(?:sk-[a-zA-Z0-9_-]{16,}|gh[pousr]_[a-zA-Z0-9_]{16,}|github_pat_[a-zA-Z0-9_]{16,}|AKIA[A-Z0-9]{16}))"#).expect("constant redaction pattern"));
    let clean = re.replace_all(&clean, "[secret redacted]");
    let urls =
        URLS.get_or_init(|| Regex::new(r#"https?://[^\s<>"'`]+"#).expect("constant URL pattern"));
    let clean = urls.replace_all(&clean, |cap: &regex::Captures<'_>| {
        let value = &cap[0];
        let (scheme, rest) = value.split_once("://").unwrap_or(("https", ""));
        let rest = rest.split(['?', '#']).next().unwrap_or("");
        let rest = rest
            .split_once('/')
            .map(|(host, path)| format!("{}/{}", host.rsplit('@').next().unwrap_or(""), path))
            .unwrap_or_else(|| rest.rsplit('@').next().unwrap_or("").to_owned());
        format!("{scheme}://{rest}")
    });
    clean.chars().take(limit).collect()
}

pub fn sensor(sensor: ProtectionSensor) {
    let mut sensors = lock(&HEALTH);
    if sensors.len() < 32 || sensors.contains_key(&sensor.id) {
        sensors.insert(sensor.id.clone(), sensor);
    }
}

pub fn health(id: &str, label: &str, state: &str, detail: &str) {
    sensor(ProtectionSensor {
        id: id.into(),
        label: label.into(),
        state: state.into(),
        detail: scrub(detail, 400),
        last_at: now_ms(),
        dropped: 0,
    });
}

pub fn keys_changed(status: &KeysStatus) {
    for (id, label, set) in [
        ("virustotal", "VirusTotal", status.virustotal),
        ("abusech", "MalwareBazaar", status.abusech),
    ] {
        health(
            &format!("reputation:{id}"),
            label,
            if set { "starting" } else { "disabled" },
            if set {
                "Key saved; checking that it works."
            } else {
                "No key is configured; online lookups for this service are disabled."
            },
        );
    }
}

/// Bounded handoff from existing blocking watchers; overflow is visible in status.
pub fn observe(observation: SecurityObservation) {
    let mut queue = lock(&QUEUE);
    if queue.len() >= MAX_QUEUE {
        queue.pop_front();
        LOST.fetch_add(1, Ordering::Relaxed);
    }
    queue.push_back(observation);
}

/// Observations that entered an incident or changed, to its history.
fn note<'a>(incident: &str, observations: impl IntoIterator<Item = &'a SecurityObservation>) {
    let records: Vec<Value> = observations.into_iter().map(|observation| json!({"incident": incident, "observation": observation})).collect();
    if !records.is_empty() {
        graph::append(OBSERVATIONS, records, 14);
    }
}

/// The incident's investigation as it is now, to its history.
fn investigated(incident: &SecurityIncident) {
    if let Some(investigation) = &incident.investigation {
        graph::append(INVESTIGATIONS, vec![json!({"incident": incident.id, "investigation": investigation})], 14);
    }
}

pub fn drain() -> Vec<SecurityObservation> {
    lock(&QUEUE).drain(..).collect()
}

pub fn security_kind(kind: &str) -> bool {
    matches!(
        kind,
        "network"
            | "lan"
            | "malware"
            | "persistence"
            | "intrusion"
            | "privacy"
            | "agent"
            | "port"
            | "cve"
    )
}

pub fn from_alert(key: &str, alert: &Alert, snapshot: &Snapshot) -> SecurityObservation {
    // Never attribute a historical alert to a reused PID. Only a newly emitted alert can use
    // the fresh snapshot; a process must predate the observation.
    let at = if alert.at == 0 { now_ms() } else { alert.at };
    let entry = alert.pid.and_then(|pid| {
        snapshot.entries.iter().find(|e| {
            e.proc.pid == pid
                && e.proc.started > 0
                && e.proc.started.saturating_mul(1000) <= at
                && snapshot.at.abs_diff(at) <= 15_000
                && alert.path.as_ref().is_none_or(|p| p == &e.exe)
        })
    });
    SecurityObservation {
        at,
        source: "watcher".into(),
        kind: alert.kind.clone(),
        severity: alert.severity.clone(),
        summary: scrub(&alert.text, 600),
        rule: key.split(':').take(2).collect::<Vec<_>>().join(":"),
        subject: entry
            .map(|e| format!("process:{}:{}", e.proc.pid, e.proc.started))
            .unwrap_or_else(|| format!("watcher:{}", digest(key))),
        pid: entry.map(|e| e.proc.pid),
        process_started: entry.map(|e| e.proc.started),
        parent_pid: entry.map(|e| e.proc.ppid),
        executable: entry.map(|e| e.exe.clone()),
        path: alert.path.clone(),
        port: alert.port,
        count: 1,
        ..Default::default()
    }
}

pub struct Store {
    pub config: ProtectionConfig,
    pub loaded: bool,
    repair_required: bool,
    incidents: VecDeque<SecurityIncident>,
    exceptions: Vec<SecurityException>,
    sensors: Vec<ProtectionSensor>,
    /// Exact observed child incarnation -> an already known parent incident entity.
    lineage: HashMap<String, (String, u64)>,
    notified: HashMap<String, (u64, u8)>,
    saved: HashMap<String, u64>,
    context: VecDeque<SecurityObservation>,
    /// Sweep group incident key -> the nodes its findings are about.
    about: HashMap<String, Vec<GraphRef>>,
}

impl Default for Store {
    fn default() -> Self {
        Self {
            config: Default::default(),
            loaded: false,
            repair_required: false,
            incidents: VecDeque::new(),
            exceptions: Vec::new(),
            sensors: Vec::new(),
            lineage: HashMap::new(),
            notified: HashMap::new(),
            saved: HashMap::new(),
            context: VecDeque::new(),
            about: HashMap::new(),
        }
    }
}

impl Store {
    pub async fn load() -> Result<Self, String> {
        let mut store = Self::default();
        let now = now_ms();
        // Before 0.1.21 the settings, exceptions and whole incidents were JSON text on
        // `ProtectionState` and `ProtectionIncident.payload`; they are moved into the setting, the
        // nodes and the streams once.
        let old = graph::query("MATCH (p:ProtectionState {key: 'local'}) WHERE p.state IS NULL OR p.state <> 'gone' RETURN p.config, p.exceptions", json!({})).await?;
        let old = old.first();
        let unset = |value: &Value| value.as_object().is_some_and(|members| members.is_empty());
        let mut config = graph::setting(CONFIG).await?;
        if let Some(text) = old.and_then(|row| row[0].as_str()).filter(|_| unset(&config)) {
            config = serde_json::from_str(text).unwrap_or(Value::Null);
        }
        if !unset(&config) {
            match serde_json::from_value::<ProtectionConfig>(config).ok().filter(|c| validate_config(c).is_ok()) {
                Some(config) => store.config = config,
                None => {
                    store.repair_required = true;
                    store.config = ProtectionConfig { packet_watch: false, deep_watch: false, investigate: false, imports: Vec::new() };
                    health(
                        "protection-state",
                        "Saved protection settings",
                        "unavailable",
                        "The saved configuration is invalid or unsupported. Protection collectors and AI are disabled; the saved setting is kept until you explicitly save repaired settings. Other system monitoring can still start.",
                    );
                }
            }
        }
        let mut gone = Vec::new();
        let mut moved = Vec::new();
        let rows = graph::query("MATCH (p:ProtectionIncident) WHERE p.payload IS NOT NULL AND (p.state IS NULL OR p.state <> 'gone') RETURN p.key, p.payload", json!({})).await?;
        for row in rows {
            let Ok(incident) = serde_json::from_str::<SecurityIncident>(row[1].as_str().unwrap_or("")) else {
                LOST.fetch_add(1, Ordering::Relaxed);
                gone.push(graph::r("ProtectionIncident", graph::text(&row[0])));
                continue;
            };
            moved.push(incident.id.clone());
            store.incidents.push_back(incident);
        }
        let rows = graph::query(
            "MATCH (p:ProtectionIncident) WHERE p.incident_key IS NOT NULL AND p.state <> 'gone' RETURN p.key, p.incident_key, p.first_at, p.last_at, p.title, p.severity, p.state, p.revision, p.omitted_observations ORDER BY p.last_at DESC LIMIT 100",
            json!({}),
        )
        .await?;
        let mut observations: HashMap<String, BTreeMap<String, SecurityObservation>> = HashMap::new();
        let mut investigations: HashMap<String, SecurityInvestigation> = HashMap::new();
        if !rows.is_empty() {
            for entry in graph::stream_read(OBSERVATIONS, now.saturating_sub(RETENTION)).await? {
                if let (Some(id), Ok(event)) = (entry.value["incident"].as_str(), serde_json::from_value::<SecurityObservation>(entry.value["observation"].clone())) {
                    observations.entry(id.to_owned()).or_default().insert(event.id.clone(), event);
                }
            }
            for entry in graph::stream_read(INVESTIGATIONS, now.saturating_sub(RETENTION)).await? {
                if let (Some(id), Ok(investigation)) = (entry.value["incident"].as_str(), serde_json::from_value(entry.value["investigation"].clone())) {
                    investigations.insert(id.to_owned(), investigation);
                }
            }
        }
        for row in rows {
            let id = graph::text(&row[0]);
            if moved.contains(&id) {
                continue;
            }
            let mut events: Vec<SecurityObservation> = observations.remove(&id).unwrap_or_default().into_values().collect();
            events.sort_by_key(|e| e.at);
            events.drain(..events.len().saturating_sub(MAX_OBSERVATIONS));
            store.incidents.push_back(SecurityIncident {
                investigation: investigations.remove(&id),
                key: graph::text(&row[1]),
                first_at: graph::number(&row[2]),
                last_at: graph::number(&row[3]),
                title: graph::text(&row[4]),
                severity: graph::text(&row[5]),
                state: graph::text(&row[6]),
                revision: graph::number(&row[7]),
                omitted_observations: graph::number(&row[8]),
                observations: events,
                id,
            });
        }
        let mut kept = VecDeque::new();
        for mut incident in std::mem::take(&mut store.incidents) {
            // Before 0.1.18 the sweep made one incident per finding; its findings are now one
            // incident per group.
            if incident.last_at.saturating_add(RETENTION) < now || incident.key.starts_with("finding:") {
                gone.push(graph::r("ProtectionIncident", &incident.id));
                continue;
            }
            incident.observations.truncate(MAX_OBSERVATIONS);
            if let Some(investigation) = incident.investigation.as_mut() {
                investigation.observations.truncate(16);
                if matches!(investigation.state.as_str(), "running" | "queued") {
                    investigation.state = "unavailable".into();
                    investigation.error = Some("CT restarted before this investigation finished. Choose Investigate to retry.".into());
                }
            }
            // Do not re-notify just because CT restarted.
            store.notified.insert(incident.id.clone(), (incident.last_at, rank(&incident.severity)));
            kept.push_back(incident);
        }
        store.incidents = kept;
        store.incidents.make_contiguous().sort_by_key(|i| i.last_at);
        let mut exceptions: Vec<SecurityException> = old.and_then(|row| row[1].as_str()).and_then(|text| serde_json::from_str(text).ok()).unwrap_or_default();
        let migrated = exceptions.len();
        let rows = graph::query("MATCH (e:ProtectionException) WHERE e.state IS NULL OR e.state <> 'gone' RETURN e.key, e.incident_key, e.created_at, e.expires_at, e.reason, e.observation_keys, e.max_severity", json!({})).await?;
        exceptions.extend(rows.iter().map(|row| SecurityException {
            id: graph::text(&row[0]),
            incident_key: graph::text(&row[1]),
            created_at: graph::number(&row[2]),
            expires_at: graph::number(&row[3]),
            reason: graph::text(&row[4]),
            observation_keys: graph::texts(&row[5]),
            max_severity: graph::text(&row[6]),
        }));
        for (n, e) in exceptions.into_iter().enumerate() {
            let valid = e.created_at <= now
                && e.expires_at > now
                && e.expires_at <= now.saturating_add(3_600_000)
                && e.expires_at <= e.created_at.saturating_add(3_600_000)
                && e.observation_keys.len() <= MAX_OBSERVATIONS
                && e.observation_keys.iter().all(|key| key.len() == 32 && key.bytes().all(|b| b.is_ascii_hexdigit()));
            if valid && store.exceptions.len() < 100 {
                if n < migrated {
                    store.save_exception(&e);
                }
                store.exceptions.push(e);
            } else if n >= migrated {
                gone.push(graph::r("ProtectionException", e.id));
            }
        }
        for incident in store.incidents.iter().filter(|i| moved.contains(&i.id)) {
            let mut batch = Self::node(incident);
            batch.units[0].nodes[0].p("payload", Value::Null).p("updated_ms", Value::Null);
            graph::put(batch);
            note(&incident.id, &incident.observations);
            investigated(incident);
        }
        if old.is_some() {
            if !store.repair_required {
                graph::set_setting(CONFIG, serde_json::to_value(&store.config).unwrap_or(Value::Null));
            }
            gone.push(graph::r("ProtectionState", "local"));
        }
        if !gone.is_empty() {
            graph::retire(gone, "security incident retention");
        }
        store.loaded = true;
        Ok(store)
    }

    fn save_config(&self) {
        if !self.loaded || self.repair_required {
            return;
        }
        graph::set_setting(CONFIG, serde_json::to_value(&self.config).unwrap_or(Value::Null));
    }

    /// An exception, `FOR` the incident it mutes (`ON` this Mac when that is no longer kept).
    fn save_exception(&self, exception: &SecurityException) {
        let mut batch = graph::Batch::new();
        let unit = batch.unit();
        unit.node("ProtectionException", &exception.id)
            .p("incident_key", exception.incident_key.clone())
            .p("created_at", exception.created_at)
            .p("expires_at", exception.expires_at)
            .p("reason", exception.reason.clone())
            .pl("observation_keys", exception.observation_keys.clone())
            .p("max_severity", exception.max_severity.clone());
        let me = graph::r("ProtectionException", &exception.id);
        match self.incidents.iter().rev().find(|i| i.key == exception.incident_key) {
            Some(incident) => {
                unit.edge(me, "FOR", graph::r("ProtectionIncident", &incident.id));
            }
            None => {
                if let Some(machine) = graph::machine() {
                    unit.edge(me, "ON", machine);
                }
            }
        }
        graph::put(batch);
    }

    /// The incident's node, `ON` this Mac and `INVOLVES` the executables of its observations.
    fn node(incident: &SecurityIncident) -> graph::Batch {
        let mut batch = graph::Batch::new();
        let unit = batch.unit();
        unit.node("ProtectionIncident", &incident.id)
            .p("incident_key", incident.key.clone())
            .p("first_at", incident.first_at)
            .p("last_at", incident.last_at)
            .p("title", incident.title.clone())
            .p("severity", incident.severity.clone())
            .p("state", incident.state.clone())
            .p("revision", incident.revision)
            .p("omitted_observations", incident.omitted_observations);
        let me = graph::r("ProtectionIncident", &incident.id);
        let mut binaries: Vec<&String> = incident.observations.iter().filter_map(|e| e.executable.as_ref()).filter(|p| p.starts_with('/')).collect();
        binaries.sort();
        binaries.dedup();
        for path in &binaries {
            unit.node("Binary", path.as_str());
            unit.edge(me.clone(), "INVOLVES", graph::r("Binary", path.as_str()));
        }
        // This Mac holds the incident: the binaries may be new with it, so they cannot.
        if let Some(machine) = graph::machine() {
            unit.edge(me, "ON", machine);
        }
        batch
    }

    /// Write the incident; `about` are the nodes its sweep group is about, linked apart so that
    /// one not in the graph refuses only that edge.
    fn save(incident: &SecurityIncident, about: &HashMap<String, Vec<GraphRef>>) {
        graph::put(Self::node(incident));
        if let Some(targets) = about.get(&incident.key) {
            let mut batch = graph::Batch::new();
            let unit = batch.unit();
            for target in targets {
                unit.edge(graph::r("ProtectionIncident", &incident.id), "ABOUT", target.clone());
            }
            graph::put(batch);
        }
    }

    /// What the sweep's findings in these groups are about (incident key -> nodes).
    pub fn set_about(&mut self, about: HashMap<String, Vec<GraphRef>>) {
        let incidents = &self.incidents;
        self.about.retain(|key, _| incidents.iter().any(|i| &i.key == key));
        self.about.extend(about);
    }

    fn prune(&mut self, now: u64) {
        let mut gone = Vec::new();
        self.exceptions.retain(|e| {
            let active = e.expires_at > now;
            if !active {
                gone.push(graph::r("ProtectionException", &e.id));
            }
            active
        });
        self.incidents.retain(|i| {
            if i.last_at.saturating_add(RETENTION) < now {
                gone.push(graph::r("ProtectionIncident", &i.id));
                false
            } else {
                true
            }
        });
        while self.incidents.len() > MAX_INCIDENTS {
            let oldest = self
                .incidents
                .iter()
                .enumerate()
                .min_by_key(|(_, i)| i.last_at)
                .map(|(n, _)| n)
                .unwrap_or(0);
            if let Some(i) = self.incidents.remove(oldest) {
                gone.push(graph::r("ProtectionIncident", i.id));
            }
        }
        if !gone.is_empty() {
            graph::retire(gone, "security incident retention");
        }
        self.lineage
            .retain(|_, (_, at)| now.saturating_sub(*at) < DAY);
        self.context.retain(|e| now.saturating_sub(e.at) < 600_000);
        self.notified
            .retain(|id, _| self.incidents.iter().any(|i| &i.id == id));
        self.saved
            .retain(|id, _| self.incidents.iter().any(|i| &i.id == id));
    }

    pub fn configure(&mut self, config: ProtectionConfig) -> Result<(), String> {
        if !self.loaded {
            return Err("Protection memory is still starting; settings were not changed.".into());
        }
        validate_config(&config)?;
        if config.investigate && !self.config.investigate {
            for incident in self
                .incidents
                .iter_mut()
                .filter(|i| i.state == "open" && rank(&i.severity) >= 2)
            {
                incident.investigation = Some(SecurityInvestigation {
                    state: "queued".into(),
                    ..Default::default()
                });
                investigated(incident);
            }
        }
        self.config = config;
        self.repair_required = false;
        self.save_config();
        health(
            "protection-state",
            "Saved protection settings",
            "active",
            "The user explicitly saved validated protection settings.",
        );
        health(
            "protection-exceptions",
            "Saved notification exceptions",
            "active",
            "Exception settings were explicitly saved after validation; no malformed exception is active.",
        );
        Ok(())
    }

    pub fn set_sensors(&mut self, sensors: Vec<ProtectionSensor>) {
        self.sensors = sensors;
    }

    /// Returns an incident only when a notification is due. Timeline facts are kept even when
    /// a precise, temporary exception suppresses an interruption.
    pub fn record(
        &mut self,
        mut event: SecurityObservation,
        snapshot: &Snapshot,
    ) -> Option<SecurityIncident> {
        if !self.loaded {
            observe(event);
            return None;
        }
        let now = now_ms();
        self.prune(now);
        if event.at == 0
            || event.at > now.saturating_add(60_000)
            || event.at.saturating_add(RETENTION) < now
        {
            return None;
        }
        event.summary = scrub(&event.summary, 600);
        event.rule = scrub(&event.rule, 120);
        event.source = scrub(&event.source, 80);
        event.subject = scrub(&event.subject, 256);
        event.kind = scrub(&event.kind, 64);
        for text in [&mut event.path, &mut event.executable] {
            if let Some(value) = text {
                *value = scrub(value, 1024);
            }
        }
        if let Some(remote) = event.remote.as_mut() {
            *remote = remote
                .parse::<std::net::IpAddr>()
                .map(|ip| ip.to_string())
                .unwrap_or_default();
        }
        event.count = event.count.clamp(1, 1_000_000);
        if event.summary.is_empty() {
            return None;
        }
        if event.id.is_empty() {
            event.id = format!("ev-{}-{}", now, SEQUENCE.fetch_add(1, Ordering::Relaxed));
        }
        if event.subject.is_empty() {
            event.subject = format!(
                "event:{}",
                digest(&format!(
                    "{}:{}:{}",
                    event.source, event.rule, event.summary
                ))
            );
        }
        // Native process identity includes executable/start. Imported sensor PID fields cannot
        // attach to a local process merely by sharing a number.
        let local = !event.source.starts_with("import:");
        let process_key = if local {
            event
                .pid
                .zip(event.process_started)
                .filter(|(_, at)| *at > 0)
                .filter(|_| {
                    event
                        .executable
                        .as_ref()
                        .is_some_and(|p| p.starts_with('/'))
                })
                .map(|(pid, at)| format!("process:{pid}:{at}"))
        } else {
            None
        };
        if let Some(key) = process_key.as_ref() {
            event.subject = key.clone();
            if matches!(event.kind.as_str(), "process_exec" | "execution" | "exec")
                && snapshot.at.abs_diff(event.at) < 10_000
            {
                if let Some(parent) = event.parent_pid.and_then(|pid| {
                    snapshot.entries.iter().find(|e| {
                        e.proc.pid == pid
                            && e.proc.started > 0
                            && e.proc.started.saturating_mul(1000) <= event.at
                    })
                }) {
                    let parent_key = format!("process:{}:{}", parent.proc.pid, parent.proc.started);
                    let root = self
                        .lineage
                        .get(&parent_key)
                        .map(|(root, _)| root.clone())
                        .unwrap_or(parent_key);
                    let observed_parent = self
                        .incidents
                        .iter()
                        .any(|i| i.key == root && i.last_at.abs_diff(event.at) <= 600_000)
                        || self.context.iter().any(|e| {
                            e.subject == root
                                && matches!(e.kind.as_str(), "process_exec" | "execution" | "exec")
                                && e.at.abs_diff(event.at) <= 120_000
                        });
                    if observed_parent
                        && event
                            .at
                            .saturating_sub(parent.proc.started.saturating_mul(1000))
                            <= 600_000
                    {
                        self.lineage.insert(key.clone(), (root, now));
                    }
                }
            }
        }
        let key = self
            .lineage
            .get(&event.subject)
            .map(|(root, _)| root.clone())
            .or_else(|| {
                self.incidents
                    .iter()
                    .rev()
                    .find(|i| {
                        i.last_at.abs_diff(event.at) < 1_800_000
                            && i.observations.iter().any(|e| e.subject == event.subject)
                    })
                    .map(|i| i.key.clone())
            })
            .unwrap_or_else(|| event.subject.clone());
        // At most one incident per exact entity in a 30-minute episode. An IP identifies the
        // observed source/destination only, never the person controlling it.
        let index = self
            .incidents
            .iter()
            .rposition(|i| i.key == key && i.last_at.abs_diff(event.at) < 1_800_000);
        if index.is_none() && rank(&event.severity) == 0 {
            if self.context.len() >= MAX_QUEUE {
                self.context.pop_front();
            }
            self.context.push_back(event);
            return None;
        }
        let created = index.is_none();
        let index = index.unwrap_or_else(|| {
            self.incidents.push_back(SecurityIncident {
                id: format!(
                    "incident-{}-{}",
                    now,
                    SEQUENCE.fetch_add(1, Ordering::Relaxed)
                ),
                key: key.clone(),
                first_at: event.at,
                last_at: event.at,
                title: event.summary.chars().take(220).collect(),
                severity: "info".into(),
                state: "open".into(),
                observations: self
                    .context
                    .iter()
                    .filter(|e| {
                        e.subject == key
                            || self
                                .lineage
                                .get(&e.subject)
                                .is_some_and(|(root, _)| root == &key)
                    })
                    .rev()
                    .take(12)
                    .cloned()
                    .collect(),
                ..Default::default()
            });
            self.incidents.len() - 1
        });
        let incident = &mut self.incidents[index];
        let fp = observation_key(&event);
        let new_pattern = !incident
            .observations
            .iter()
            .any(|old| observation_key(old) == fp);
        let mut new_evidence = true;
        let mut changed = event.clone();
        if let Some(old) = incident
            .observations
            .iter_mut()
            .find(|old| observation_key(old) == fp && old.summary == event.summary)
        {
            old.count = old.count.saturating_add(event.count);
            changed = old.clone();
            new_evidence = false;
        } else {
            incident.observations.push(event.clone());
            // Preserve the highest-value evidence and newest events; never silently pretend
            // this bounded timeline contains every event.
            if incident.observations.len() > MAX_OBSERVATIONS {
                let remove = incident
                    .observations
                    .iter()
                    .position(|e| rank(&e.severity) <= 1)
                    .unwrap_or(0);
                incident.observations.remove(remove);
                incident.omitted_observations = incident.omitted_observations.saturating_add(1);
            }
        }
        incident.first_at = incident.first_at.min(event.at);
        incident.last_at = incident.last_at.max(event.at);
        let previous_rank = rank(&incident.severity);
        if rank(&event.severity) > previous_rank {
            incident.severity = normal_severity(&event.severity).into();
            incident.title = event.summary.chars().take(220).collect();
        }
        // A credential observation plus actual outbound network evidence from the same exact
        // process/observed lineage is suspicious. It proves neither secret contents nor theft.
        let credential = incident
            .observations
            .iter()
            .any(|e| matches!(e.kind.as_str(), "credential_access" | "credential"));
        let network = incident
            .observations
            .iter()
            .any(|e| e.kind == "outbound" && e.remote.is_some());
        let persistence = incident
            .observations
            .iter()
            .any(|e| matches!(e.kind.as_str(), "persistence" | "persistence_write"));
        if credential && (network || persistence) {
            incident.severity = "high".into();
            incident.title = "Credential access and related network or startup activity; review the recorded evidence.".into();
        }
        if new_evidence
            && (rank(&incident.severity) > previous_rank
                || (new_pattern && rank(&event.severity) >= 2))
            && incident.state == "dismissed"
        {
            incident.state = "open".into();
            self.notified.remove(&incident.id);
        }
        if new_evidence {
            incident.revision = incident.revision.saturating_add(1);
            if self.config.investigate
                && rank(&incident.severity) >= 2
                && incident.state == "open"
                && incident
                    .investigation
                    .as_ref()
                    .is_none_or(|i| !matches!(i.state.as_str(), "running" | "queued"))
            {
                let last_check = incident
                    .investigation
                    .as_ref()
                    .map(|i| i.checked_at)
                    .unwrap_or(0);
                // Keep the new work queued even if the quiet-period budget has not elapsed;
                // otherwise one isolated new finding could remain uninvestigated forever.
                incident.investigation = Some(SecurityInvestigation {
                    state: "queued".into(),
                    checked_at: if rank(&incident.severity) > previous_rank {
                        0
                    } else {
                        last_check
                    },
                    ..Default::default()
                });
                investigated(incident);
            }
        }
        if created {
            note(&incident.id, &incident.observations);
        }
        if new_evidence || now.saturating_sub(*self.saved.get(&incident.id).unwrap_or(&0)) > 30_000
        {
            Self::save(incident, &self.about);
            if !created {
                note(&incident.id, [&changed]);
            }
            self.saved.insert(incident.id.clone(), now);
        }
        let excepted = self.exceptions.iter().any(|e| {
            e.incident_key == incident.key
                && e.expires_at > now
                && e.observation_keys.contains(&fp)
                && current_rank_covered(&incident.severity, &e.max_severity)
        });
        let current_rank = rank(&incident.severity);
        let notify = !excepted
            && incident.state == "open"
            && current_rank >= 2
            && self
                .notified
                .get(&incident.id)
                .is_none_or(|(last_at, old_rank)| {
                    current_rank > *old_rank
                        || (new_pattern
                            && rank(&event.severity) >= 2
                            && now.saturating_sub(*last_at) > 60_000)
                });
        let result = if notify {
            self.notified
                .insert(incident.id.clone(), (now, current_rank));
            Some(incident.clone())
        } else {
            None
        };
        self.prune(now);
        result
    }

    pub fn incident(&self, id: &str) -> Option<SecurityIncident> {
        self.incidents.iter().find(|i| i.id == id).cloned()
    }

    pub fn incidents(&self) -> impl Iterator<Item = &SecurityIncident> {
        self.incidents.iter()
    }

    /// The person decided about what these incidents are about: their open ones are dismissed.
    pub fn dismiss(&mut self, key: &str) {
        for incident in self.incidents.iter_mut().filter(|i| i.key == key && i.state == "open") {
            incident.state = "dismissed".into();
            incident.revision = incident.revision.saturating_add(1);
            Self::save(incident, &self.about);
        }
    }

    /// Every open incident is dismissed (a clean plate before a sweep).
    pub fn dismiss_all(&mut self) {
        for incident in self.incidents.iter_mut().filter(|i| i.state == "open") {
            incident.state = "dismissed".into();
            incident.revision = incident.revision.saturating_add(1);
            Self::save(incident, &self.about);
        }
    }

    pub fn action(&mut self, action: &ProtectionAction) -> Result<(), String> {
        if !self.loaded {
            return Err("Protection memory is still starting.".into());
        }
        if self.repair_required
            && matches!(action.action.as_str(), "allow_hour" | "revoke_exception")
        {
            return Err(
                "Repair and save protection settings before changing notification exceptions."
                    .into(),
            );
        }
        self.prune(now_ms());
        if action.action == "revoke_exception" {
            let before = self.exceptions.len();
            self.exceptions.retain(|e| e.id != action.id);
            if before == self.exceptions.len() {
                return Err("The exception is no longer active.".into());
            }
            graph::retire(vec![graph::r("ProtectionException", &action.id)], "revoked");
            return Ok(());
        }
        let incident = self
            .incidents
            .iter_mut()
            .find(|i| i.id == action.id)
            .ok_or("That incident is no longer retained.")?;
        match action.action.as_str() {
            "dismiss" => incident.state = "dismissed".into(),
            "reopen" => incident.state = "open".into(),
            "allow_hour" => {
                if !action.confirm {
                    return Err(
                        "Confirm the one-hour exception for this exact incident entity.".into(),
                    );
                }
                if action.expected_revision != Some(incident.revision) {
                    return Err(
                        "The incident changed; review its current patterns before muting them."
                            .into(),
                    );
                }
                let now = now_ms();
                let replaced: Vec<_> = self.exceptions.iter().filter(|e| e.incident_key == incident.key).map(|e| graph::r("ProtectionException", &e.id)).collect();
                if self.exceptions.len() - replaced.len() >= 100 {
                    return Err("Remove an existing exception first (maximum 100).".into());
                }
                self.exceptions.retain(|e| e.incident_key != incident.key);
                if !replaced.is_empty() {
                    graph::retire(replaced, "replaced");
                }
                self.exceptions.push(SecurityException { id: format!("exception-{}-{}", now, SEQUENCE.fetch_add(1, Ordering::Relaxed)), incident_key: incident.key.clone(), created_at: now, expires_at: now + 3_600_000, reason: "User muted the recorded patterns for this exact entity for one hour; new behaviours and severity escalations are not covered. Collection continues.".into(), observation_keys: incident.observations.iter().map(observation_key).collect(), max_severity: incident.severity.clone() });
            }
            "investigate" => {
                if !self.config.investigate {
                    return Err("Enable AI investigation first.".into());
                }
                if incident
                    .investigation
                    .as_ref()
                    .is_some_and(|i| i.state == "running")
                {
                    return Err("An investigation of this incident is already running.".into());
                }
                incident.investigation = Some(SecurityInvestigation {
                    state: "queued".into(),
                    ..Default::default()
                });
                investigated(incident);
            }
            _ => return Err("Unsupported incident action.".into()),
        }
        incident.revision = incident.revision.saturating_add(1);
        Self::save(incident, &self.about);
        if action.action == "allow_hour" && let Some(exception) = self.exceptions.last() {
            self.save_exception(exception);
        }
        Ok(())
    }

    pub fn next_investigation(&mut self) -> Option<SecurityIncident> {
        if !self.loaded || !self.config.investigate {
            return None;
        }
        let incident = self
            .incidents
            .iter_mut()
            .filter(|i| {
                i.state == "open"
                    && i.investigation.as_ref().is_some_and(|v| {
                        v.state == "queued"
                            && (v.checked_at == 0
                                || now_ms().saturating_sub(v.checked_at) >= 300_000)
                    })
            })
            .max_by_key(|i| (rank(&i.severity), i.last_at))?;
        incident.investigation = Some(SecurityInvestigation {
            state: "running".into(),
            checked_at: now_ms(),
            ..Default::default()
        });
        investigated(incident);
        Some(incident.clone())
    }

    pub fn finish_investigation(&mut self, id: &str, revision: u64, result: SecurityInvestigation) {
        let Some(incident) = self.incidents.iter_mut().find(|i| i.id == id) else {
            return;
        };
        if !self.config.investigate || incident.state != "open" {
            incident.investigation = Some(SecurityInvestigation {
                state: "unavailable".into(),
                checked_at: now_ms(),
                error: Some(
                    "Investigation disabled or incident dismissed while it was running.".into(),
                ),
                ..Default::default()
            });
        } else if incident.revision != revision {
            // A changed timeline invalidates a conclusion; rerun after the debounce interval.
            incident.investigation = Some(SecurityInvestigation {
                state: "queued".into(),
                checked_at: now_ms(),
                error: Some("New evidence arrived; the previous conclusion was discarded.".into()),
                ..Default::default()
            });
        } else {
            incident.investigation = Some(result);
        }
        investigated(incident);
    }

    pub fn status(&mut self) -> ProtectionStatus {
        let now = now_ms();
        self.prune(now);
        let mut sensors = self.sensors.clone();
        sensors.extend(lock(&HEALTH).values().cloned());
        sensors.extend(crate::feeds::protection_health());
        for sensor in &mut sensors {
            if sensor.state == "active"
                && now.saturating_sub(sensor.last_at) > 90_000
                && !sensor.id.starts_with("reputation:")
                && !sensor.id.starts_with("feed:")
                && !matches!(
                    sensor.id.as_str(),
                    "protection-state" | "protection-exceptions"
                )
            {
                sensor.state = "degraded".into();
                sensor.detail = format!("No recent collector heartbeat. {}", sensor.detail);
            }
        }
        sensors.push(ProtectionSensor { id: "incident-memory".into(), label: "Local incident memory".into(), state: if self.loaded && graph::ready() && graph::refused() == 0 { if graph::pending() > 100 || graph::dropped() > 0 || LOST.load(Ordering::Relaxed) > 0 { "degraded" } else { "active" } } else { "unavailable" }.into(), detail: format!("{} pending graph writes; {} refused writes; {} outbox writes lost. Up to 100 incidents / 64 facts each, kept 14 days. Timelines are bounded, not a complete audit log.", graph::pending(), graph::refused(), graph::dropped()), last_at: now, dropped: LOST.load(Ordering::Relaxed).saturating_add(graph::dropped() as u64) });
        let mut incidents: Vec<_> = self.incidents.iter().cloned().collect();
        incidents.sort_by_key(|i| std::cmp::Reverse(i.last_at));
        incidents.truncate(MAX_INCIDENTS);
        ProtectionStatus {
            at: now, config: self.config.clone(), sensors,
            incidents,
            exceptions: self.exceptions.clone(),
            deep_install_command: None,
            deep_service: false,
            packet_capture_help: "Packet monitoring needs access to macOS BPF capture devices. CT never requests sudo automatically. If unavailable, connection watching still runs; scan detection does not. Capture observes selected interface metadata, without packet payload retention.".into(),
            visibility: "This Mac and explicitly configured local sensor logs. Other devices' unicast traffic and probes stopped at your router are not automatically visible. Packet loss, sleep, VPNs and missing permissions can leave gaps; no findings is not an all-clear.".into(),
        }
    }
}

pub fn validate_config(config: &ProtectionConfig) -> Result<(), String> {
    if config.imports.len() > 4 {
        return Err("At most four local sensor logs may be configured.".into());
    }
    let mut seen = std::collections::HashSet::new();
    for input in &config.imports {
        if !matches!(input.kind.as_str(), "suricata" | "zeek") {
            return Err("Sensor format must be suricata or zeek JSON.".into());
        }
        let path = std::path::Path::new(&input.path);
        if input.path.len() > 1024
            || input.path.chars().any(char::is_control)
            || !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(
                "Select an absolute local log path without parent traversal or control characters."
                    .into(),
            );
        }
        if !seen.insert(input.path.clone()) {
            return Err("A sensor log may be selected only once.".into());
        }
    }
    Ok(())
}

pub fn rank(value: &str) -> u8 {
    match value {
        "critical" | "high" => 3,
        "medium" | "warn" => 2,
        "low" => 1,
        _ => 0,
    }
}
pub fn normal_severity(value: &str) -> &str {
    match rank(value) {
        3 => "high",
        2 => "medium",
        1 => "low",
        _ => "info",
    }
}

fn current_rank_covered(current: &str, allowed: &str) -> bool {
    rank(current) <= rank(allowed)
}

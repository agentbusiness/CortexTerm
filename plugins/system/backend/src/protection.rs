//! Local security incidents. Collection is facts; correlation and severity are code; the model
//! can gather bounded read-only evidence and explain it. Nothing in this module runs a shell.
//! State is app-local in IronGraph. A missing collector is never an all-clear.

use crate::graph::{self, Props};
use crate::procs::Snapshot;
use crate::util::now_ms;
use cc_protocol::contracts::system::*;
use regex::Regex;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

const DAY: u64 = 86_400_000;
const RETENTION: u64 = 14 * DAY;
const MAX_INCIDENTS: usize = 100;
const MAX_OBSERVATIONS: usize = 64;
const MAX_QUEUE: usize = 2048;
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static LOST: AtomicU64 = AtomicU64::new(0);
static QUEUE: Mutex<VecDeque<SecurityObservation>> = Mutex::new(VecDeque::new());
static HEALTH: Mutex<BTreeMap<String, ProtectionSensor>> = Mutex::new(BTreeMap::new());

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
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
                "Key saved. No authenticated lookup has been verified in this session yet; a saved key is not a successful check."
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
        }
    }
}

impl Store {
    pub async fn load() -> Result<Self, String> {
        let mut store = Self::default();
        let rows = graph::query(
            "MATCH (p:ProtectionState {key: 'local'}) RETURN p.config, p.exceptions",
            json!({}),
        )
        .await?;
        if let Some(row) = rows.first() {
            if let Some(text) = row.first().and_then(|v| v.as_str()) {
                let config = if text.len() <= 64 * 1024 {
                    serde_json::from_str::<ProtectionConfig>(text)
                        .ok()
                        .filter(|c| validate_config(c).is_ok())
                } else {
                    None
                };
                if let Some(config) = config {
                    store.config = config;
                } else {
                    store.repair_required = true;
                    store.config = ProtectionConfig {
                        packet_watch: false,
                        deep_watch: false,
                        investigate: false,
                        imports: Vec::new(),
                    };
                    health(
                        "protection-state",
                        "Saved protection settings",
                        "unavailable",
                        "The saved configuration is invalid or unsupported. Protection collectors and AI are disabled; the original graph payload is preserved until you explicitly save repaired settings. Other system monitoring can still start.",
                    );
                }
            }
            if let Some(text) = row.get(1).and_then(|v| v.as_str()) {
                if text.len() <= 256 * 1024 {
                    if let Ok(exceptions) = serde_json::from_str(text) {
                        store.exceptions = exceptions;
                    } else {
                        store.repair_required = true;
                        health(
                            "protection-exceptions",
                            "Saved notification exceptions",
                            "degraded",
                            "Saved exceptions were invalid and are not active. The original payload is preserved until settings are explicitly saved.",
                        );
                    }
                } else {
                    store.repair_required = true;
                    health(
                        "protection-exceptions",
                        "Saved notification exceptions",
                        "degraded",
                        "Saved exceptions exceeded the storage limit and are not active.",
                    );
                }
                store.exceptions.retain(|e| {
                    e.created_at <= now_ms()
                        && e.expires_at > now_ms()
                        && e.expires_at <= now_ms().saturating_add(3_600_000)
                        && e.expires_at <= e.created_at.saturating_add(3_600_000)
                        && e.observation_keys.len() <= MAX_OBSERVATIONS
                        && e.observation_keys.iter().all(|key| {
                            key.len() == 32 && key.bytes().all(|b| b.is_ascii_hexdigit())
                        })
                });
                store.exceptions.truncate(100);
            }
        }
        let rows = graph::query("MATCH (p:ProtectionIncident) WHERE p.state IS NULL OR p.state <> 'gone' RETURN p.payload ORDER BY p.updated_ms DESC LIMIT 100", json!({})).await?;
        for row in rows {
            let Some(text) = row
                .first()
                .and_then(|v| v.as_str())
                .filter(|s| s.len() <= 1_048_576)
            else {
                LOST.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            let Ok(mut incident) = serde_json::from_str::<SecurityIncident>(text) else {
                LOST.fetch_add(1, Ordering::Relaxed);
                continue;
            };
            if incident.last_at.saturating_add(RETENTION) < now_ms() {
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
            store.notified.insert(
                incident.id.clone(),
                (incident.last_at, rank(&incident.severity)),
            );
            store.incidents.push_back(incident);
        }
        store.incidents.make_contiguous().sort_by_key(|i| i.last_at);
        store.loaded = true;
        Ok(store)
    }

    fn save_config(&self) {
        if !self.loaded || self.repair_required {
            return;
        }
        let mut batch = graph::Batch::new();
        let unit = batch.unit();
        unit.node("ProtectionState", "local")
            .p(
                "config",
                serde_json::to_string(&self.config).unwrap_or_default(),
            )
            .p(
                "exceptions",
                serde_json::to_string(&self.exceptions).unwrap_or_default(),
            );
        if let Some(machine) = graph::machine() {
            unit.edge(graph::r("ProtectionState", "local"), "ON", machine);
        }
        graph::put(batch);
    }

    fn save(incident: &SecurityIncident) {
        let mut batch = graph::Batch::new();
        let unit = batch.unit();
        unit.node("ProtectionIncident", &incident.id)
            .p("updated_ms", incident.last_at)
            .p(
                "payload",
                serde_json::to_string(incident).unwrap_or_default(),
            );
        if let Some(machine) = graph::machine() {
            unit.edge(graph::r("ProtectionIncident", &incident.id), "ON", machine);
        }
        graph::put(batch);
    }

    fn prune(&mut self, now: u64) {
        let before = self.exceptions.len();
        self.exceptions.retain(|e| e.expires_at > now);
        if before != self.exceptions.len() {
            self.save_config();
        }
        let mut gone = Vec::new();
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
                Self::save(incident);
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
        if let Some(old) = incident
            .observations
            .iter_mut()
            .find(|old| observation_key(old) == fp && old.summary == event.summary)
        {
            old.count = old.count.saturating_add(event.count);
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
            }
        }
        if new_evidence || now.saturating_sub(*self.saved.get(&incident.id).unwrap_or(&0)) > 30_000
        {
            Self::save(incident);
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
            self.save_config();
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
                self.exceptions.retain(|e| e.incident_key != incident.key);
                if self.exceptions.len() >= 100 {
                    return Err("Remove an existing exception first (maximum 100).".into());
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
            }
            _ => return Err("Unsupported incident action.".into()),
        }
        incident.revision = incident.revision.saturating_add(1);
        Self::save(incident);
        self.save_config();
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
        Self::save(incident);
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
        Self::save(incident);
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
            deep_capture_command: None,
            deep_install_command: None,
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
fn normal_severity(value: &str) -> &str {
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

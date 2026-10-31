//! Bounded, no-follow local sensor ingestion. Initial attachment starts at EOF so a historical
//! capture never appears to be a current attack. Rotation and truncation are explicit gaps.

use super::time;
use cc_protocol::contracts::system::{ProtectionSensor, SecurityObservation};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::IpAddr;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const READ_BYTES: usize = 512 * 1024;
const LINE_BYTES: usize = 64 * 1024;
const MAX_EVENTS: usize = 256;
const FRESH_MS: u64 = 120_000;

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Endpoint,
    Suricata,
    Zeek,
}
impl Kind {
    pub fn parse(kind: &str) -> Option<Self> {
        match kind {
            "suricata" => Some(Self::Suricata),
            "zeek" => Some(Self::Zeek),
            _ => None,
        }
    }
}

pub(super) fn open_regular(path: &Path) -> Result<File, String> {
    if !path.is_absolute() {
        return Err("Select an absolute path to a local sensor file.".into());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|e| format!("Cannot open sensor file: {e}"))?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    let uid = unsafe { libc::geteuid() };
    if !meta.is_file()
        || ![0, uid].contains(&meta.uid())
        || meta.mode() & 0o022 != 0
        || meta.nlink() != 1
    {
        return Err("Sensor file must be a regular, single-link file owned by you or root and not writable by group or others; symbolic links are refused.".into());
    }
    Ok(file)
}

pub(super) struct Tail {
    identity: Option<(u64, u64)>,
    offset: u64,
    marker: Vec<u8>,
    pending: Vec<u8>,
    discarding: bool,
    attached_at: u64,
    last_good: u64,
    dropped: u64,
    producer_dropped: u64,
    parser_unknown: u64,
    stopped: bool,
    scans: HashMap<(String, String), (u64, BTreeSet<u16>, u64)>,
    sweeps: HashMap<(String, u16), (u64, BTreeSet<String>, u64)>,
}

impl Tail {
    pub fn new() -> Self {
        Self {
            identity: None,
            offset: 0,
            marker: Vec::new(),
            pending: Vec::new(),
            discarding: false,
            attached_at: 0,
            last_good: 0,
            dropped: 0,
            producer_dropped: 0,
            parser_unknown: 0,
            stopped: false,
            scans: HashMap::new(),
            sweeps: HashMap::new(),
        }
    }
    pub fn reset(&mut self) {
        *self = Self::new();
    }

    pub fn read(
        &mut self,
        path: &Path,
        kind: Kind,
        id: &str,
        label: &str,
    ) -> (Vec<SecurityObservation>, ProtectionSensor) {
        let now = crate::util::now_ms();
        let mut status = ProtectionSensor {
            id: id.into(),
            label: label.into(),
            state: "starting".into(),
            dropped: self.dropped + self.producer_dropped,
            last_at: self.last_good,
            ..Default::default()
        };
        let fail = |mut status: ProtectionSensor, detail: String| {
            status.state = "unavailable".into();
            status.detail = detail;
            (Vec::new(), status)
        };
        let mut file = match open_regular(path) {
            Ok(file) => file,
            Err(error) => return fail(status, error),
        };
        let meta = match file.metadata() {
            Ok(meta) => meta,
            Err(error) => return fail(status, error.to_string()),
        };
        let identity = (meta.dev(), meta.ino());
        if self.identity.is_none() {
            self.identity = Some(identity);
            self.offset = meta.len();
            self.attached_at = now;
            self.marker = match continuity_marker(&mut file, self.offset) {
                Ok(marker) => marker,
                Err(error) => return fail(status, error),
            };
            self.discarding = self.marker.last().is_some_and(|byte| *byte != b'\n');
            status.detail = "Attached at the end of the file; waiting for fresh, validated sensor output. Historical records are not replayed as live alerts.".into();
            return (Vec::new(), status);
        }
        let rewritten = if self.identity == Some(identity) && meta.len() >= self.offset {
            match continuity_marker(&mut file, self.offset) {
                Ok(marker) => marker != self.marker,
                Err(error) => return fail(status, error),
            }
        } else {
            false
        };
        let changed = self.identity != Some(identity) || meta.len() < self.offset || rewritten;
        if changed {
            self.dropped = self.dropped.saturating_add(1);
            self.identity = Some(identity);
            self.offset = 0;
            self.marker.clear();
            self.pending.clear();
            self.discarding = false;
            self.scans.clear();
            self.sweeps.clear();
        }
        if let Err(error) = file.seek(SeekFrom::Start(self.offset)) {
            return fail(status, format!("Cannot seek sensor file: {error}"));
        }
        let mut bytes = Vec::with_capacity(READ_BYTES);
        if let Err(error) = (&mut file).take(READ_BYTES as u64).read_to_end(&mut bytes) {
            return fail(status, format!("Cannot read sensor file: {error}"));
        }
        self.offset = self.offset.saturating_add(bytes.len() as u64);
        self.marker = match continuity_marker(&mut file, self.offset) {
            Ok(marker) => marker,
            Err(error) => return fail(status, error),
        };
        let mut events = Vec::new();
        let mut records = 0usize;
        for byte in bytes {
            if byte != b'\n' {
                if !self.discarding {
                    if self.pending.len() < LINE_BYTES {
                        self.pending.push(byte);
                    } else {
                        self.pending.clear();
                        self.discarding = true;
                        self.dropped = self.dropped.saturating_add(1);
                    }
                }
                continue;
            }
            if self.discarding {
                self.discarding = false;
                continue;
            }
            let line = std::mem::take(&mut self.pending);
            records += 1;
            if records > 4096 {
                self.dropped = self.dropped.saturating_add(1);
                continue;
            }
            if line.is_empty() {
                continue;
            }
            let value: Value = match serde_json::from_slice(&line) {
                Ok(value) => value,
                Err(_) => {
                    self.parser_unknown = self.parser_unknown.saturating_add(1);
                    continue;
                }
            };
            let parsed = self.parse(kind, &value, now, id);
            for mut event in parsed {
                if event.at < self.attached_at.saturating_sub(5000)
                    || event.at > now.saturating_add(60_000)
                    || now.saturating_sub(event.at) > 600_000
                {
                    self.dropped = self.dropped.saturating_add(1);
                    continue;
                }
                if events.len() >= MAX_EVENTS {
                    self.dropped = self.dropped.saturating_add(1);
                    continue;
                }
                event.id.clear();
                events.push(event);
            }
        }
        status.last_at = self.last_good;
        status.dropped = self.dropped.saturating_add(self.producer_dropped);
        let behind = meta.len().saturating_sub(self.offset);
        status.state = if self.stopped {
            "unavailable"
        } else if self.last_good == 0 {
            if now.saturating_sub(self.attached_at) <= FRESH_MS {
                "starting"
            } else {
                "degraded"
            }
        } else if now.saturating_sub(self.last_good) > FRESH_MS
            || behind > 0
            || self.parser_unknown > 0
            || status.dropped > 0
        {
            "degraded"
        } else {
            "active"
        }
        .into();
        status.detail = format!(
            "Local metadata only. Last validated record {}; {} bytes pending; {} malformed or unsupported records. {}{}",
            if self.last_good == 0 {
                "not received".into()
            } else {
                format!("{} seconds ago", now.saturating_sub(self.last_good) / 1000)
            },
            behind,
            self.parser_unknown,
            if matches!(kind, Kind::Endpoint) && self.stopped {
                "The native producer ended; deep capture is stopped."
            } else if matches!(kind, Kind::Endpoint) {
                "Native Endpoint Security sensor must remain running with its required permissions."
            } else {
                "Coverage is limited to traffic observed by the selected network sensor; an idle log does not prove connectivity."
            },
            if changed {
                " File rotated or truncated; continuity is incomplete."
            } else {
                ""
            }
        );
        (events, status)
    }

    fn parse(&mut self, kind: Kind, value: &Value, now: u64, id: &str) -> Vec<SecurityObservation> {
        match kind {
            Kind::Endpoint => {
                if value["schema"] != 1 {
                    self.parser_unknown = self.parser_unknown.saturating_add(1);
                    return Vec::new();
                }
                let Some(at) = value["at"]
                    .as_u64()
                    .filter(|at| *at <= now + 60_000 && now.saturating_sub(*at) < FRESH_MS)
                else {
                    self.parser_unknown = self.parser_unknown.saturating_add(1);
                    return Vec::new();
                };
                self.last_good = at;
                self.stopped = value["record"] == "stopped";
                self.producer_dropped = self
                    .producer_dropped
                    .max(value["dropped"].as_u64().unwrap_or(0));
                if value["record"] == "heartbeat" || self.stopped {
                    return Vec::new();
                }
                match endpoint_observation(&value["observation"]) {
                    Some(event) => vec![event],
                    None => {
                        self.parser_unknown = self.parser_unknown.saturating_add(1);
                        Vec::new()
                    }
                }
            }
            Kind::Suricata => {
                let Some(at) = time::timestamp(&value["timestamp"]) else {
                    self.parser_unknown += 1;
                    return Vec::new();
                };
                if at > now + 60_000 || now.saturating_sub(at) > 600_000 {
                    return Vec::new();
                }
                self.last_good = at;
                let (Some(source), Some(dest)) = (ip(&value["src_ip"]), ip(&value["dest_ip"]))
                else {
                    return Vec::new();
                };
                if value["event_type"] != "alert" {
                    return Vec::new();
                }
                let Some(sid) = value["alert"]["signature_id"].as_u64() else {
                    self.parser_unknown += 1;
                    return Vec::new();
                };
                vec![SecurityObservation {
                    at,
                    source: format!("import:{id}"),
                    kind: "network_alert".into(),
                    severity: match value["alert"]["severity"].as_u64() {
                        Some(1) => "high",
                        Some(2) => "medium",
                        _ => "low",
                    }
                    .into(),
                    summary: format!(
                        "The selected Suricata sensor reported rule {sid} on traffic from {source} to {dest}; this is a sensor finding, not proof of successful intrusion."
                    ),
                    rule: format!("suricata:{sid}"),
                    subject: format!("network:{source}:{dest}:{sid}"),
                    remote: Some(source),
                    port: value["dest_port"]
                        .as_u64()
                        .and_then(|n| u16::try_from(n).ok()),
                    count: 1,
                    ..Default::default()
                }]
            }
            Kind::Zeek => {
                let Some(at) = time::timestamp(&value["ts"]) else {
                    self.parser_unknown += 1;
                    return Vec::new();
                };
                if at > now + 60_000 || now.saturating_sub(at) > 600_000 {
                    return Vec::new();
                }
                self.last_good = at;
                let (Some(source), Some(dest), Some(port)) = (
                    ip(&value["id.orig_h"]),
                    ip(&value["id.resp_h"]),
                    value["id.resp_p"]
                        .as_u64()
                        .and_then(|n| u16::try_from(n).ok()),
                ) else {
                    self.parser_unknown += 1;
                    return Vec::new();
                };
                if value["proto"] != "tcp"
                    || !matches!(
                        value["conn_state"].as_str(),
                        Some("S0" | "REJ" | "RSTOS0" | "SH")
                    )
                {
                    return Vec::new();
                }
                self.scans
                    .retain(|_, (seen, _, _)| now.saturating_sub(*seen) < 60_000);
                self.sweeps
                    .retain(|_, (seen, _, _)| now.saturating_sub(*seen) < 60_000);
                let mut observations = Vec::new();
                let sweep_key = (source.clone(), port);
                if self.sweeps.len() < 2048 || self.sweeps.contains_key(&sweep_key) {
                    let bucket = self
                        .sweeps
                        .entry(sweep_key)
                        .or_insert_with(|| (at, BTreeSet::new(), 0));
                    if bucket.1.len() < 128 {
                        bucket.1.insert(dest.clone());
                    }
                    if bucket.1.len() >= 20 && bucket.2 == 0 {
                        bucket.2 = at;
                        observations.push(SecurityObservation {
                            at, source: format!("import:{id}"), kind: "network_sweep".into(), severity: "medium".into(),
                            summary: format!("The selected Zeek sensor saw {source} make failed TCP connection attempts to {} different hosts on port {port} within 60 seconds. This resembles an address sweep; legitimate network tools can do this too.", bucket.1.len()),
                            rule: "network.address_sweep".into(), subject: format!("external-sweep:{id}:{source}:{port}"), remote: Some(source.clone()), port: Some(port), count: bucket.1.len() as u64, ..Default::default()
                        });
                    }
                } else {
                    self.dropped = self.dropped.saturating_add(1);
                }
                if self.scans.len() >= 2048
                    && !self.scans.contains_key(&(source.clone(), dest.clone()))
                {
                    self.dropped = self.dropped.saturating_add(1);
                    return observations;
                }
                let bucket = self
                    .scans
                    .entry((source.clone(), dest.clone()))
                    .or_insert_with(|| (at, BTreeSet::new(), 0));
                if bucket.1.len() < 128 {
                    bucket.1.insert(port);
                }
                if bucket.1.len() < 20 || bucket.2 > 0 {
                    return observations;
                }
                bucket.2 = at;
                observations.push(SecurityObservation {
                    at, source: format!("import:{id}"), kind: "port_scan".into(), severity: "medium".into(),
                    summary: format!("The selected Zeek sensor saw {source} make failed TCP connection attempts to {} distinct ports on {dest} within 60 seconds. Attempts do not establish successful access.", bucket.1.len()),
                    rule: "network.port_scan".into(), subject: format!("scan:{source}:{dest}"), remote: Some(source), count: bucket.1.len() as u64, ..Default::default()
                });
                observations
            }
        }
    }
}

fn continuity_marker(file: &mut File, offset: u64) -> Result<Vec<u8>, String> {
    let begin = offset.saturating_sub(64);
    file.seek(SeekFrom::Start(begin))
        .map_err(|e| format!("Cannot inspect sensor continuity: {e}"))?;
    let mut marker = vec![0; (offset - begin) as usize];
    file.read_exact(&mut marker)
        .map_err(|e| format!("Sensor changed during its continuity check: {e}"))?;
    Ok(marker)
}

fn ip(value: &Value) -> Option<String> {
    value
        .as_str()?
        .parse::<IpAddr>()
        .ok()
        .map(|ip| ip.to_string())
}

/// The endpoint producer and stdin sink share this strict allow-list. Raw JSON fields such as
/// command arguments, environment, file contents and arbitrary summary text cannot pass through.
pub(super) fn endpoint_observation(value: &Value) -> Option<SecurityObservation> {
    let at = value["at"].as_u64()?;
    let pid = value["pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)?;
    let started = value["process_started"].as_u64().filter(|n| *n > 0)?;
    let started_us = value["process_started_us"]
        .as_u64()
        .filter(|n| *n / 1_000_000 == started)?;
    let process_version = value["process_version"]
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())?;
    let executable = path(&value["executable"])?;
    let parent = value["parent_pid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0);
    let kind = value["kind"].as_str()?;
    let observed_path = path(&value["path"]);
    if kind != "process_exec" && observed_path.is_none() {
        return None;
    }
    let (severity, rule, summary) = match kind {
        "process_exec" => (
            "info",
            "endpoint.exec",
            "A process executed; its arguments and environment were not collected.",
        ),
        "credential_access" => (
            "medium",
            "endpoint.credential_access",
            "A process opened a credential-related file. Opening it does not establish that its contents were read or stolen.",
        ),
        "credential_owner_access" => (
            "info",
            "endpoint.credential_owner_access",
            "A recognized credential-store owner opened its own store. This is routine context, not proof that the process is uncompromised.",
        ),
        "persistence_write" => (
            "medium",
            "endpoint.persistence_write",
            "A process modified a startup or persistence-related file.",
        ),
        "archive_created" => (
            "low",
            "endpoint.archive_created",
            "A process created or modified an archive file; purpose and contents are unknown.",
        ),
        "file_rename" => (
            "info",
            "endpoint.file_rename",
            "A process renamed a file in the monitored home directory.",
        ),
        "file_unlink" => (
            "info",
            "endpoint.file_unlink",
            "A process removed a file in the monitored home directory.",
        ),
        "file_write" => (
            "info",
            "endpoint.file_write",
            "A process modified a file in the monitored home directory.",
        ),
        "bulk_file_change"
            if value["count"]
                .as_u64()
                .is_some_and(|n| (50..=256).contains(&n)) =>
        {
            (
                "medium",
                "endpoint.bulk_file_change",
                "A process modified, renamed or removed at least 50 different home-directory files within 30 seconds. This may be a normal batch operation; the changes alone do not establish ransomware.",
            )
        }
        _ => return None,
    };
    Some(SecurityObservation {
        at,
        pid: Some(pid),
        process_started: Some(started),
        process_started_us: Some(started_us),
        process_version: Some(process_version),
        parent_pid: parent,
        executable: Some(executable),
        path: observed_path,
        kind: kind.into(),
        severity: severity.into(),
        rule: rule.into(),
        summary: summary.into(),
        source: "endpoint".into(),
        subject: format!("process:{pid}:{started}"),
        count: if kind == "bulk_file_change" {
            value["count"].as_u64().unwrap_or(50)
        } else {
            1
        },
        ..Default::default()
    })
}

fn path(value: &Value) -> Option<String> {
    let value = value.as_str()?;
    (value.starts_with('/') && value.len() <= 4096 && !value.chars().any(|c| c.is_control() || matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{feff}')))
        .then(|| value.to_owned())
}

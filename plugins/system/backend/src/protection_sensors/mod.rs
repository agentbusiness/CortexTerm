//! Metadata-only protection collectors. No collector grants itself privilege, opens a listener,
//! or interprets model text. The native Endpoint Security producer is explicitly user-started.

mod endpoint;
mod input;
mod packet;
mod time;

use crate::procs::Snapshot;
use cc_protocol::contracts::system::{ProtectionConfig, ProtectionSensor, SecurityObservation};
pub use endpoint::{deep_capture_command, deep_install_command, endpoint_capture};
use std::collections::HashMap;

pub struct Collection {
    pub observations: Vec<SecurityObservation>,
    pub sensors: Vec<ProtectionSensor>,
}

pub struct Collector {
    packet: packet::PacketWatch,
    endpoint: input::Tail,
    imports: HashMap<String, input::Tail>,
    dropped: u64,
}

impl Collector {
    pub fn new() -> Self {
        Self {
            packet: packet::PacketWatch::new(),
            endpoint: input::Tail::new(),
            imports: HashMap::new(),
            dropped: 0,
        }
    }

    /// Blocking, bounded work; the caller runs this outside the asynchronous runtime's workers.
    pub fn collect(&mut self, config: &ProtectionConfig, _snapshot: &Snapshot) -> Collection {
        let mut result = self.packet.collect(config.packet_watch);
        if config.deep_watch {
            let path = crate::util::data_dir().join("protection-events.jsonl");
            let (events, status) =
                self.endpoint
                    .read(&path, input::Kind::Endpoint, "endpoint", "Endpoint events");
            result.observations.extend(events);
            result.sensors.push(status);
        } else {
            self.endpoint.reset();
            result.sensors.push(ProtectionSensor {
                id: "endpoint".into(), label: "Endpoint events".into(), state: "disabled".into(),
                detail: "Deep monitoring is off. Enabling it does not install or start a privileged collector.".into(),
                ..Default::default()
            });
        }
        self.imports.retain(|key, _| {
            config
                .imports
                .iter()
                .take(4)
                .any(|source| format!("{}:{}", source.kind, source.path) == *key)
        });
        for (index, source) in config.imports.iter().take(4).enumerate() {
            let id = format!("network-import-{index}");
            let label = format!("Network sensor {}", index + 1);
            let Some(kind) = input::Kind::parse(&source.kind) else {
                result.sensors.push(ProtectionSensor { id, label, state: "unavailable".into(), detail: "Unsupported sensor format; select Suricata EVE JSON or Zeek JSON connection logs.".into(), ..Default::default() });
                continue;
            };
            let key = format!("{}:{}", source.kind, source.path);
            let tail = self.imports.entry(key).or_insert_with(input::Tail::new);
            let (events, status) = tail.read(std::path::Path::new(&source.path), kind, &id, &label);
            result.observations.extend(events);
            result.sensors.push(status);
        }
        let excess = result.observations.len().saturating_sub(1024);
        self.dropped = self.dropped.saturating_add(excess as u64);
        result.observations.truncate(1024);
        result.sensors.push(ProtectionSensor {
            id: "collector-budget".into(), label: "Event collection budget".into(),
            state: if self.dropped == 0 { "active" } else { "degraded" }.into(),
            detail: "At most 1,024 observations enter protection per collection cycle. Over-budget observations are counted as lost; coverage is incomplete after a loss.".into(),
            last_at: crate::util::now_ms(), dropped: self.dropped,
        });
        result
    }
}

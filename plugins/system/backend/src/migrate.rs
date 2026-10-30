//! Once: what earlier versions kept as files in the data folder (`sweep.json`, `ignored.json`,
//! `alerts.json`, `schedules.json`, `traces.json`, `netwatch.json`, `netdigest.json`, `lan.json`,
//! `persistence.json`, `agents.json`, `ports.json`, `cve/`, `feeds/`, `deep/`) is moved into the
//! graph, in the shapes the modules load, and the files are deleted once memory took every write.
//! The secret keys (`keys/`) are moved into the Keychain by `keys::import_files`.

use crate::findings;
use crate::graph::{self, Batch, Props, r};
use crate::util::{data_dir, now_ms};
use cc_protocol::contracts::memory::TraceInfo;
use cc_protocol::contracts::system::{Alert, ScheduleList, SweepReport};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Feeds earlier versions kept that nothing reads any more.
const RETIRED_FEEDS: &[&str] = &["cisa-kev.json", "cisa-kev-v2.json"];

#[derive(Default, Debug)]
pub struct Moved {
    pub counts: BTreeMap<&'static str, usize>,
    pub files: Vec<PathBuf>,
}

fn read<T: for<'a> Deserialize<'a>>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    match serde_json::from_slice(&bytes) {
        Ok(value) => Some(value),
        Err(error) => {
            tracing::warn!("migrate: {} is unreadable ({error}); it is left as it is", path.display());
            None
        }
    }
}

fn at(batch: &mut Batch, ms: u64) {
    batch.at_ms = Some(ms.min(now_ms()));
}

/// Move what the files hold into the graph. Returns what was moved (nothing when there are no
/// files). Called once memory answered, before the modules load.
pub async fn run() -> Moved {
    let dir = data_dir();
    let mut moved = Moved::default();
    let Some(machine) = graph::machine() else { return moved };
    let started = std::time::Instant::now();
    let refused_before = graph::refused();
    let count = |what: &'static str, n: usize, file: PathBuf, moved: &mut Moved| {
        *moved.counts.entry(what).or_default() += n;
        moved.files.push(file);
    };

    // Feeds, with the time each was fetched.
    for entry in std::fs::read_dir(dir.join("feeds")).into_iter().flatten().flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if RETIRED_FEEDS.contains(&name.as_str()) || name.ends_with(".tmp") || name.ends_with(".part") {
            count("old feed files dropped", 1, path, &mut moved);
            continue;
        }
        let url = crate::feeds::url_of(&name)
            .map(str::to_owned)
            .or_else(|| crate::inventory::FEEDS.iter().find(|(n, _)| *n == name).map(|(_, u)| (*u).to_owned()))
            .or_else(|| name.strip_prefix("eol-").and_then(|r| r.strip_suffix(".json")).map(|p| format!("https://endoflife.date/api/{p}.json")));
        let Some(url) = url else {
            tracing::warn!("migrate: feeds/{name} is not a known list; it is left as it is");
            continue;
        };
        let fetched = std::fs::metadata(&path).and_then(|m| m.modified()).ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
        let Ok(bytes) = std::fs::read(&path) else { continue };
        let size = bytes.len();
        if let Some(batches) = crate::docs::batches(&name, &url, &bytes, fetched) {
            for batch in batches {
                graph::put(batch);
            }
            count("feeds", 1, path, &mut moved);
            *moved.counts.entry("feed bytes").or_default() += size;
        }
    }

    // The lists first: the network baseline below names each network's owner from them.
    graph::flush(Duration::from_secs(300)).await;
    let _ = crate::docs::load_index().await;

    // The last sweep, then the findings the person ignored.
    let mut store = findings::Store::default();
    let path = dir.join("sweep.json");
    if let Some(report) = read::<SweepReport>(&path) {
        if report.at != 0 {
            let mut seen = Batch::new();
            at(&mut seen, report.at);
            let n = report.findings.len();
            store.record(&report, seen);
            count("sweep findings", n, path, &mut moved);
        } else {
            count("sweep findings", 0, path, &mut moved);
        }
    }
    let path = dir.join("ignored.json");
    if let Some(keys) = read::<Vec<String>>(&path) {
        let mut n = 0;
        for key in &keys {
            if store.ignore(key, true).is_ok() {
                n += 1;
            }
        }
        count("ignored findings", n, path, &mut moved);
    }

    // Alerts.
    let path = dir.join("alerts.json");
    if let Some(old) = read::<OldAlerts>(&path) {
        let now = now_ms();
        let mut records = Vec::new();
        for stored in &old.alerts {
            let a = &stored.alert;
            let mut batch = Batch::new();
            at(&mut batch, a.at);
            let unit = batch.unit();
            unit.node("AlertKind", a.kind.clone());
            unit.edge(r("AlertKind", a.kind.clone()), "ON", machine.clone());
            let quiet = old.quiet.get(&stored.key).copied().filter(|until| *until > now);
            unit.node("Alert", a.id.clone())
                .p("kind", a.kind.clone())
                .p("severity", a.severity.clone())
                .p("text", a.text.clone())
                .p("at", a.at)
                .p("subject", stored.key.clone())
                .po("pid", a.pid)
                .po("port", a.port)
                .po("path", a.path.clone())
                .pl("actions", a.actions.clone())
                .p("dismissed", a.dismissed)
                .po("quiet_until", quiet);
            unit.edge(r("Alert", a.id.clone()), "OF", r("AlertKind", a.kind.clone()));
            graph::put(batch);
            records.push(crate::alerts::stream_record(a, &stored.key));
        }
        for kind in &old.ignored_kinds {
            let mut batch = Batch::new();
            let unit = batch.unit();
            unit.node("AlertKind", kind.clone()).t("ignored", true);
            unit.edge(r("AlertKind", kind.clone()), "ON", machine.clone());
            graph::put(batch);
        }
        graph::append("alerts", records, 365);
        count("alerts", old.alerts.len(), path, &mut moved);
    }

    // Schedules (written as they load: `Store::start`).
    let path = dir.join("schedules.json");
    if let Some(list) = read::<ScheduleList>(&path) {
        let n = list.schedules.len();
        let _ = crate::schedule::Store::start(list, false);
        count("schedules", n, path, &mut moved);
    }

    // Recordings that were live.
    let path = dir.join("traces.json");
    if let Some(list) = read::<Vec<OldTrace>>(&path) {
        let n = list.len();
        for t in list {
            if let Some(batch) = crate::tracer::recording_batch(&t.info, t.root, t.with_root, t.since, t.root_started) {
                graph::put(batch);
            }
        }
        count("live traces", n, path, &mut moved);
    }

    // The network watcher's baseline: programs, their networks, hourly uploads.
    let path = dir.join("netwatch.json");
    if let Some(state) = read::<OldWatch>(&path) {
        let tables = tokio::task::spawn_blocking(crate::feeds::tables).await.ok();
        let mut n = 0;
        let mut uploads = Vec::new();
        for (trust, profile) in &state.apps {
            let key = trust.strip_prefix("path:").map(str::to_owned).unwrap_or_else(|| trust.clone());
            let me = r("Binary", key.clone());
            let mut batch = Batch::new();
            at(&mut batch, state.since.max(1));
            let unit = batch.unit();
            let team = trust.strip_prefix("team:").and_then(|rest| rest.split(':').next());
            let node = unit.node("Binary", key.clone());
            node.p("trust", trust.clone()).p("app", profile.name.clone());
            if let Some(team) = team {
                node.p("team", team).p("signed", "signed");
                unit.node("Signer", team);
                unit.edge(me.clone(), "SIGNED_BY", r("Signer", team));
            }
            let ports: Vec<u64> = profile.ports.iter().map(|p| u64::from(*p)).collect();
            for asn in &profile.asns {
                let owner = tables.as_ref().map(|t| t.asn_owner(*asn)).unwrap_or_default();
                unit.node("Network", asn.to_string()).ps("owner", &owner.name).ps("country", &owner.country);
                unit.edge(me.clone(), "CONNECTED", r("Network", asn.to_string())).t("bytes_out", 0u64).t("bytes_in", 0u64).p("ports", ports.clone());
            }
            if profile.asns.is_empty() {
                continue;
            }
            n += 1;
            graph::put(batch);
            let len = profile.hours.len() as u64;
            for (i, bytes) in profile.hours.iter().enumerate() {
                if *bytes > 0 && profile.hour >= len - i as u64 {
                    uploads.push(json!({"trust": trust, "hour": profile.hour - (len - i as u64), "bytes": bytes}));
                }
            }
        }
        for exe in &state.unsigned_seen {
            let mut batch = Batch::new();
            let unit = batch.unit();
            unit.node("Binary", exe.clone()).p("flagged_online", true);
            let folder = graph::folder(unit, Path::new(exe).parent().unwrap_or(Path::new("/")));
            unit.edge(r("Binary", exe.clone()), "IN", folder);
            graph::put(batch);
        }
        graph::append(crate::netwatch::UPLOAD_TOPIC, uploads, 14);
        count("programs online", n, path, &mut moved);
    }
    let path = dir.join("netdigest.json");
    if let Some(notes) = read::<Vec<Value>>(&path) {
        let n = notes.len();
        graph::append(crate::netwatch::DIGEST_TOPIC, notes, 7);
        count("network notes", n, path, &mut moved);
    }

    // This Mac's networks and the devices on them.
    let path = dir.join("lan.json");
    if let Some(lan) = read::<OldLan>(&path) {
        let mut devices = 0;
        for known in lan.networks.values() {
            let net = &known.net;
            let mut batch = Batch::new();
            at(&mut batch, known.first.max(1));
            let unit = batch.unit();
            unit.node("Lan", net.key.clone())
                .p("ssid", net.ssid.clone())
                .p("interface", net.interface.clone())
                .p("router", net.router.clone())
                .pl("dns", net.dns.clone())
                .pl("router6", net.router6.clone())
                .pl("public6", net.public6.clone())
                .t("router_mac", net.router_mac.clone())
                .t("dhcp_server", net.dhcp_server.clone())
                .t("security", net.security.clone());
            unit.edge(machine.clone(), "JOINED", r("Lan", net.key.clone()));
            graph::put(batch);
            for (key, d) in &known.devices {
                // Twice: first seen, then last seen (the ON edge keeps both).
                for when in [d.first, d.last] {
                    let mut batch = Batch::new();
                    at(&mut batch, when.max(1));
                    let unit = batch.unit();
                    unit.node("Device", key.clone()).p("ip", d.ip.clone()).p("mac", d.mac.clone()).ps("name", &d.name).ps("vendor", &d.vendor);
                    unit.edge(r("Device", key.clone()), "ON", r("Lan", net.key.clone()));
                    graph::put(batch);
                }
                devices += 1;
            }
        }
        if lan.greynoise_at > 0 {
            let mut batch = Batch::new();
            at(&mut batch, lan.greynoise_at);
            let unit = batch.unit();
            unit.node("MacSetting", "greynoise").t("value", lan.greynoise.clone().unwrap_or_else(|| "quiet".into())).p("checked_ms", lan.greynoise_at);
            unit.edge(r("MacSetting", "greynoise"), "OF", machine.clone());
            graph::put(batch);
        }
        count("networks", lan.networks.len(), path.clone(), &mut moved);
        *moved.counts.entry("devices").or_default() += devices;
    }

    // What starts by itself, and its month of changes.
    let path = dir.join("persistence.json");
    if let Some(baseline) = read::<crate::persist::Baseline>(&path) {
        let mut batch = Batch::new();
        at(&mut batch, baseline.at.max(1));
        for (key, item) in baseline.items.iter().filter(|(k, _)| k.len() <= 1000) {
            batch.units.push(crate::persist::item_unit(key, item, &machine));
        }
        graph::put(batch);
        let changes: Vec<Value> = baseline.changes.iter().filter_map(|c| serde_json::to_value(c).ok()).collect();
        graph::append(crate::persist::CHANGES, changes, 30);
        count("start items", baseline.items.len(), path, &mut moved);
        *moved.counts.entry("persistence changes").or_default() += baseline.changes.len();
    }

    // The MCP definitions remembered.
    let path = dir.join("agents.json");
    if let Some(pins) = read::<OldPins>(&path) {
        let mut batch = Batch::new();
        for (id, pin) in &pins.servers {
            let (file, name) = id.rsplit_once('#').unwrap_or((id.as_str(), ""));
            let shown = file.split(" (").next().unwrap_or(file);
            let config = match shown.strip_prefix("~/") {
                Some(rest) => crate::util::home().join(rest).display().to_string(),
                None => shown.to_owned(),
            };
            let unit = batch.unit();
            unit.node("AgentConfig", config.clone());
            unit.edge(r("AgentConfig", config.clone()), "ON", machine.clone());
            unit.node("McpServer", id.clone()).p("name", name).p("command", pin.command.clone()).pl("args", pin.args.clone()).p("url", pin.url.clone()).t("hash", pin.hash.clone());
            unit.edge(r("AgentConfig", config), "DEFINES", r("McpServer", id.clone()));
        }
        graph::put(batch);
        count("MCP servers", pins.servers.len(), path, &mut moved);
    }

    // Listening ports seen, by when they were last seen.
    let path = dir.join("ports.json");
    if let Some(ports) = read::<OldPorts>(&path) {
        let mut by_time: BTreeMap<u64, Vec<&String>> = BTreeMap::new();
        for (key, seen) in &ports.seen {
            by_time.entry(*seen).or_default().push(key);
        }
        for (seen, keys) in by_time {
            let mut batch = Batch::new();
            at(&mut batch, seen.max(1));
            for key in keys {
                let unit = batch.unit();
                let (process, port) = key.rsplit_once(':').unwrap_or((key.as_str(), ""));
                unit.node("Port", key.clone()).p("process", process).po("port", port.parse::<u64>().ok());
                unit.edge(r("Port", key.clone()), "ON", machine.clone());
            }
            graph::put(batch);
        }
        count("ports", ports.seen.len(), path, &mut moved);
    }

    // Advisories.
    for entry in std::fs::read_dir(dir.join("cve")).into_iter().flatten().flatten() {
        let path = entry.path();
        let Some(id) = path.file_stem().map(|s| s.to_string_lossy().into_owned()) else { continue };
        match std::fs::read(&path).ok().and_then(|bytes| crate::cve::migrated_advisory(&id, &bytes)) {
            Some(batch) => {
                graph::put(batch);
                count("advisories", 1, path, &mut moved);
            }
            None => tracing::warn!("migrate: {} is unreadable; it is left as it is", path.display()),
        }
    }

    // Root-only outputs: into the temporary folder the sweep reads them from now.
    for name in ["btm.txt", "eslogger.jsonl"] {
        let from = dir.join("deep").join(name);
        if from.is_file() {
            let to = crate::deep::dir().join(name);
            let _ = std::fs::create_dir_all(crate::deep::dir());
            if std::fs::rename(&from, &to).is_ok() {
                *moved.counts.entry("deep outputs").or_default() += 1;
            }
        }
    }

    if moved.files.is_empty() && moved.counts.is_empty() {
        return moved;
    }
    // Every write taken: the files go. A refused one keeps them, to try again next start.
    let sent = graph::flush(Duration::from_secs(600)).await;
    let refused = graph::refused() - refused_before;
    if sent && refused == 0 {
        for file in &moved.files {
            let _ = std::fs::remove_file(file);
        }
        for sub in ["cve", "feeds", "deep"] {
            let _ = std::fs::remove_dir(dir.join(sub));
        }
        tracing::warn!("moved the old files into the graph in {} ms: {:?}", started.elapsed().as_millis(), moved.counts);
    } else {
        tracing::warn!("moving the old files into the graph: {refused} writes refused (sent all: {sent}); the files stay for the next start");
        moved.files.clear();
    }
    moved
}

#[derive(Deserialize)]
struct OldStoredAlert {
    #[serde(flatten)]
    alert: Alert,
    key: String,
}

#[derive(Deserialize, Default)]
struct OldAlerts {
    #[serde(default)]
    alerts: Vec<OldStoredAlert>,
    #[serde(default)]
    quiet: HashMap<String, u64>,
    #[serde(default)]
    ignored_kinds: Vec<String>,
}

#[derive(Deserialize)]
struct OldTrace {
    info: TraceInfo,
    root: u32,
    #[serde(default = "yes")]
    with_root: bool,
    #[serde(default)]
    since: u64,
    #[serde(default)]
    root_started: u64,
}

fn yes() -> bool {
    true
}

#[derive(Deserialize, Default)]
struct OldProfile {
    #[serde(default)]
    name: String,
    #[serde(default)]
    asns: BTreeSet<u32>,
    #[serde(default)]
    ports: BTreeSet<u16>,
    #[serde(default)]
    hours: Vec<u64>,
    #[serde(default)]
    hour: u64,
}

#[derive(Deserialize, Default)]
struct OldWatch {
    #[serde(default)]
    since: u64,
    #[serde(default)]
    apps: HashMap<String, OldProfile>,
    #[serde(default)]
    unsigned_seen: BTreeSet<String>,
}

#[derive(Deserialize, Default)]
struct OldNet {
    #[serde(default)]
    key: String,
    #[serde(default)]
    ssid: String,
    #[serde(default)]
    interface: String,
    #[serde(default)]
    router: String,
    #[serde(default)]
    router_mac: String,
    #[serde(default)]
    dhcp_server: String,
    #[serde(default)]
    dns: Vec<String>,
    #[serde(default)]
    router6: Vec<String>,
    #[serde(default)]
    security: String,
    #[serde(default)]
    public6: Vec<String>,
}

#[derive(Deserialize, Default)]
struct OldDevice {
    #[serde(default)]
    ip: String,
    #[serde(default)]
    mac: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    vendor: String,
    #[serde(default)]
    first: u64,
    #[serde(default)]
    last: u64,
}

#[derive(Deserialize, Default)]
struct OldKnown {
    #[serde(default)]
    net: OldNet,
    #[serde(default)]
    first: u64,
    #[serde(default)]
    devices: BTreeMap<String, OldDevice>,
}

#[derive(Deserialize, Default)]
struct OldLan {
    #[serde(default)]
    networks: BTreeMap<String, OldKnown>,
    #[serde(default)]
    greynoise_at: u64,
    #[serde(default)]
    greynoise: Option<String>,
}

#[derive(Deserialize, Default)]
struct OldPin {
    #[serde(default)]
    hash: String,
    #[serde(default)]
    command: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    url: String,
}

#[derive(Deserialize, Default)]
struct OldPins {
    #[serde(default)]
    servers: BTreeMap<String, OldPin>,
}

#[derive(Deserialize, Default)]
struct OldPorts {
    #[serde(default)]
    seen: HashMap<String, u64>,
}

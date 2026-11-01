//! The network watcher: every 15 s one `nettop` sample gives each process's connections and the
//! bytes they moved (Apple's NetworkStatistics, no root). Each remote address is named by its owner
//! network and country, and checked against the cached threat lists.
//!
//! It interrupts (alerts) only for high-confidence signs: a threat-list address, a stealer's drop
//! (Telegram's network, Discord webhooks, paste and file-drop sites, tunnels) from an app that has
//! no business there, an unsigned or quarantined program online for the first time, a regular
//! "call home" rhythm to a small network, an upload far above the app's normal, a gateway change.
//! Everything else goes into the network digest, which the sweep lists.
//!
//! The first 7 days only learn: each app's networks, countries and ports, and its hourly upload.
//! Apps are known by their signer (team), so an update does not look new. A flagged process that
//! a terminal command started names that command.
//!
//! What it learns is kept in the graph: each program online as `(:Binary {key: path, trust, app,
//! signed, team, flagged_online})-[:ON]->(:Machine)`, the networks it talks to as `(:Binary)-[:CONNECTED
//! {bytes_out*, bytes_in*, ports}]->(:Network {key: ASN, owner, country})` (bytes counted since it
//! was first seen), its hourly upload in the stream `net.upload` (14 days) and the digest in the
//! stream `net.digest` (a week).

use crate::alerts::Candidate;
use crate::feeds;
use crate::graph::{self, Batch, Props, r};
use crate::procs::Snapshot;
use crate::util::{now_ms, shorten};
use cc_protocol::contracts::system::Alert;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const HOUR: u64 = 3_600_000;
const DAY: u64 = 24 * HOUR;
/// Quiet learning after the first start.
const LEARN: u64 = 7 * DAY;
/// Hourly upload kept per app (14 days).
const HOURS: usize = 14 * 24;
const MB: u64 = 1_000_000;

/// Networks too big to judge a rhythm or a first by (clouds, CDNs, Apple).
const MAJOR: &[u32] = &[714, 6185, 13335, 15169, 396982, 16509, 14618, 8075, 8068, 20940, 16625, 54113, 32934, 36459, 2906];
const TELEGRAM: &[u32] = &[62041, 59930, 62014, 44907, 211157];
/// Where stolen data is sent; matched in a process's command line.
const DROPS: &[&str] = &[
    "api.telegram.org",
    "discord.com/api/webhooks",
    "discordapp.com/api/webhooks",
    "pastebin.com",
    "paste.ee",
    "hastebin.com",
    "transfer.sh",
    "gofile.io",
    "file.io",
    "catbox.moe",
    "anonfiles",
    "ngrok.io",
    "ngrok-free.app",
    "ngrok.app",
    "trycloudflare.com",
];
const MESSENGERS_AND_BROWSERS: &[&str] = &[
    "Telegram",
    "Telegram Desktop",
    "Discord",
    "Safari",
    "Google Chrome",
    "Google Chrome Canary",
    "Chromium",
    "Firefox",
    "Arc",
    "Brave Browser",
    "Microsoft Edge",
    "Opera",
    "Vivaldi",
    "Orion",
    "Zen",
];
const MAIL_APPS: &[&str] = &["Mail", "Microsoft Outlook", "Thunderbird", "Spark", "Spark Desktop", "Airmail 5", "Mimestream", "Canary Mail", "Postbox"];
const ODD_PORTS: &[u16] = &[4444, 1337, 6667, 6668, 6669, 31337];

// ---------------------------------------------------------------------------------------------
// The digest: what is worth knowing but not worth an interruption. The sweep lists it.

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Note {
    pub at: u64,
    /// The app, or "Network" for this Mac's network.
    pub app: String,
    /// network | lan
    pub kind: String,
    /// medium | low | info
    pub severity: String,
    pub text: String,
}

static DIGEST: Mutex<Option<Vec<Note>>> = Mutex::new(None);

/// The digest's stream.
pub const DIGEST_TOPIC: &str = "net.digest";
/// Hourly upload per program.
pub const UPLOAD_TOPIC: &str = "net.upload";

/// The last week's digest, from its stream (at start).
pub async fn load_digest() -> Result<usize, String> {
    let since = now_ms().saturating_sub(7 * DAY);
    let mut notes: Vec<Note> = Vec::new();
    for entry in graph::stream_read(DIGEST_TOPIC, since).await? {
        let Ok(note) = serde_json::from_value::<Note>(entry.value) else { continue };
        // A repeat refreshes the note's time.
        notes.retain(|n| !(n.app == note.app && n.text == note.text));
        notes.push(note);
    }
    let count = notes.len();
    if let Ok(mut slot) = DIGEST.lock() {
        *slot = Some(notes);
    }
    Ok(count)
}

/// Add to the digest (a repeat only refreshes its time); a week is kept. Nothing before the
/// graph is loaded.
pub fn note(app: &str, kind: &str, severity: &str, text: String) {
    let Ok(mut slot) = DIGEST.lock() else { return };
    let Some(notes) = slot.as_mut() else { return };
    let now = now_ms();
    notes.retain(|n| now.saturating_sub(n.at) < 7 * DAY);
    let written = match notes.iter_mut().find(|n| n.app == app && n.text == text) {
        // A repeat is written at most once an hour.
        Some(existing) if now.saturating_sub(existing.at) < HOUR => return,
        Some(existing) => {
            existing.at = now;
            existing.clone()
        }
        None => {
            let note = Note { at: now, app: app.into(), kind: kind.into(), severity: severity.into(), text };
            notes.push(note.clone());
            note
        }
    };
    if notes.len() > 400 {
        let excess = notes.len() - 400;
        notes.drain(..excess);
    }
    graph::append(DIGEST_TOPIC, vec![serde_json::to_value(&written).unwrap_or_default()], 7);
}

/// The last week's digest, oldest first.
pub fn digest() -> Vec<Note> {
    let Ok(slot) = DIGEST.lock() else { return Vec::new() };
    let now = now_ms();
    let Some(notes) = slot.as_ref() else { return Vec::new() };
    let mut list: Vec<Note> = notes.iter().filter(|n| now.saturating_sub(n.at) < 7 * DAY).cloned().collect();
    list.sort_by_key(|n| n.at);
    list
}

// ---------------------------------------------------------------------------------------------
// One nettop sample.

struct Flow {
    proto: String,
    local_port: u16,
    remote: IpAddr,
    remote_port: u16,
    bytes_in: u64,
    bytes_out: u64,
    counted: bool,
}

/// pid -> (name, its flows with a remote end).
#[cfg(target_os = "macos")]
fn sample() -> Result<HashMap<u32, (String, Vec<Flow>)>, String> {
    let out = crate::util::run("/usr/bin/nettop", &["-L", "1", "-x", "-n", "-J", "bytes_in,bytes_out"], Duration::from_secs(10))?;
    if !out.ok {
        return Err(format!("nettop: {}", out.stderr.trim()));
    }
    let mut by_pid: HashMap<u32, (String, Vec<Flow>)> = HashMap::new();
    let mut current: Option<u32> = None;
    for line in out.stdout.lines().skip(1) {
        let fields: Vec<&str> = line.split(',').collect();
        let first = fields.first().copied().unwrap_or("");
        if let Some((proto, ends)) = first.split_once(' ')
            && let Some((local, remote)) = ends.split_once("<->")
            && ["tcp4", "tcp6", "udp4", "udp6", "quic4", "quic6"].contains(&proto)
        {
            let (Some(pid), Some((_, local_port)), Some((remote, remote_port))) = (current, endpoint(local), endpoint(remote)) else { continue };
            let bytes_in = fields.get(1).and_then(|f| f.parse().ok()).unwrap_or(0);
            let bytes_out = fields.get(2).and_then(|f| f.parse().ok()).unwrap_or(0);
            if let Some((_, flows)) = by_pid.get_mut(&pid) {
                flows.push(Flow { proto: proto.trim_end_matches(['4', '6']).to_owned(), local_port, remote, remote_port, bytes_in, bytes_out, counted: true });
            }
            continue;
        }
        // A process row: `name.pid`.
        current = first.rsplit_once('.').and_then(|(name, pid)| {
            let pid = pid.parse::<u32>().ok()?;
            by_pid.entry(pid).or_insert_with(|| (name.to_owned(), Vec::new()));
            Some(pid)
        });
    }
    Ok(by_pid)
}

/// `1.2.3.4:443` or `2001:db8::1%en0.443`; `None` for a wildcard end.
#[cfg(target_os = "linux")]
fn sample() -> Result<HashMap<u32, (String, Vec<Flow>)>, String> {
    let owners = crate::linux::socket_owners();
    let mut result: HashMap<u32, (String, Vec<Flow>)> = HashMap::new();
    for socket in crate::linux::sockets().map_err(|error| error.to_string())?.into_values() {
        if socket.remote.ip().is_unspecified() || socket.remote.port() == 0 { continue; }
        for (pid, name) in owners.get(&socket.inode).into_iter().flatten() {
            let (_, flows) = result.entry(*pid).or_insert_with(|| (name.clone(), Vec::new()));
            flows.push(Flow { proto: socket.proto.into(), local_port: socket.local.port(), remote: socket.remote.ip(), remote_port: socket.remote.port(), bytes_in: 0, bytes_out: 0, counted: false });
        }
    }
    Ok(result)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn sample() -> Result<HashMap<u32, (String, Vec<Flow>)>, String> { Err("network watcher is unavailable on this OS".into()) }

#[cfg(target_os = "macos")]
fn endpoint(text: &str) -> Option<(IpAddr, u16)> {
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => (host, port),
        _ => text.rsplit_once('.')?,
    };
    let host = host.split('%').next().unwrap_or(host);
    Some((host.parse().ok()?, port.parse().ok()?))
}

/// On the internet (not this Mac, the LAN, link-local, carrier NAT or multicast).
pub fn public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_broadcast()
                || a.is_unspecified()
                || o[0] == 0
                || o[0] >= 240
                || (o[0] == 100 && o[1] & 0xc0 == 64))
        }
        IpAddr::V6(a) => {
            if let Some(v4) = a.to_ipv4_mapped() {
                return public(IpAddr::V4(v4));
            }
            let s = a.segments()[0];
            !(a.is_loopback() || a.is_unspecified() || a.is_multicast() || s & 0xfe00 == 0xfc00 || s & 0xffc0 == 0xfe80)
        }
    }
}

// ---------------------------------------------------------------------------------------------
// What is remembered.

/// One network a program talks to: bytes since it was first seen, and the remote ports.
#[derive(Debug, Default, Clone)]
struct NetUse {
    owner: String,
    country: String,
    bytes_out: u64,
    bytes_in: u64,
    ports: BTreeSet<u16>,
}

#[derive(Debug, Default)]
struct Profile {
    /// The name shown ("Slack").
    name: String,
    /// The program's path (its `Binary` node); empty when unknown.
    exe: String,
    signed: String,
    team: String,
    asns: BTreeSet<u32>,
    countries: BTreeSet<String>,
    ports: BTreeSet<u16>,
    /// Upload per hour, oldest first.
    hours: VecDeque<u64>,
    /// The hour (Unix ms / HOUR) `hour_bytes` counts.
    hour: u64,
    hour_bytes: u64,
    /// Per network (ASN).
    nets: HashMap<u32, NetUse>,
    /// Changed since it was last written.
    dirty: bool,
}

#[derive(Debug, Default)]
struct State {
    /// When watching began (the learning week counts from here).
    since: u64,
    /// Trust key ("team:ABCD1234:Slack", "apple:Safari", "path:/tmp/x") -> what it does.
    apps: HashMap<String, Profile>,
    /// Unsigned programs already seen online, by path.
    unsigned_seen: BTreeSet<String>,
}

/// The watcher's memory, from the graph: every program's networks and the last 14 days of
/// hourly uploads. `since` is when the first connection was recorded.
async fn load_state() -> Result<State, String> {
    let mut state = State::default();
    let rows = graph::query_all(
        "MATCH (b:Binary)-[c:CONNECTED]->(n:Network) WHERE b.trust IS NOT NULL \
         RETURN b.trust, b.app, b.key, b.signed, b.team, n.key, n.owner, n.country, c.bytes_out, c.bytes_in, c.ports, c.first_ms ORDER BY b.key, n.key",
        json!({}),
    )
    .await?;
    let mut since = u64::MAX;
    for row in rows {
        let trust = graph::text(&row[0]);
        let profile = state.apps.entry(trust).or_default();
        profile.name = graph::text(&row[1]);
        profile.exe = graph::text(&row[2]);
        profile.signed = graph::text(&row[3]);
        profile.team = graph::text(&row[4]);
        let asn: u32 = graph::text(&row[5]).parse().unwrap_or(0);
        let ports: BTreeSet<u16> = row[10].as_array().into_iter().flatten().filter_map(|p| p.as_u64()).map(|p| p as u16).collect();
        let usage = NetUse { owner: graph::text(&row[6]), country: graph::text(&row[7]), bytes_out: graph::number(&row[8]), bytes_in: graph::number(&row[9]), ports: ports.clone() };
        if !usage.country.is_empty() {
            profile.countries.insert(usage.country.clone());
        }
        profile.asns.insert(asn);
        profile.ports.extend(ports);
        profile.nets.insert(asn, usage);
        since = since.min(graph::number(&row[11]).max(1));
    }
    let rows = graph::query_all("MATCH (b:Binary) WHERE b.flagged_online = true RETURN b.key ORDER BY b.key", json!({})).await?;
    state.unsigned_seen = rows.iter().map(|row| graph::text(&row[0])).collect();
    // Hourly uploads: per program, from its first hour to now, idle hours as 0.
    let now_hour = now_ms() / HOUR;
    let mut hours: HashMap<String, std::collections::BTreeMap<u64, u64>> = HashMap::new();
    for entry in graph::stream_read(UPLOAD_TOPIC, now_ms().saturating_sub(HOURS as u64 * HOUR)).await? {
        let (Some(trust), Some(hour), Some(bytes)) = (entry.value["trust"].as_str(), entry.value["hour"].as_u64(), entry.value["bytes"].as_u64()) else { continue };
        *hours.entry(trust.to_owned()).or_default().entry(hour).or_default() += bytes;
    }
    for (trust, by_hour) in hours {
        let profile = state.apps.entry(trust).or_default();
        let first = *by_hour.keys().next().unwrap_or(&now_hour);
        profile.hours = (first..now_hour).map(|h| by_hour.get(&h).copied().unwrap_or(0)).collect();
        while profile.hours.len() > HOURS {
            profile.hours.pop_front();
        }
        profile.hour = now_hour;
    }
    state.since = if since == u64::MAX { now_ms() } else { since };
    Ok(state)
}

/// One process, as the watcher judges it (cached by pid).
#[derive(Clone)]
struct ProcInfo {
    name: String,
    app: String,
    exe: String,
    command: String,
    /// Trust key: by signer when signed, by path when not.
    key: String,
    /// Not signed, or only ad-hoc.
    unsigned: bool,
    /// Only ad-hoc signed (what every local build is on Apple silicon).
    adhoc: bool,
    quarantined: bool,
    /// Runs from a temporary or download folder.
    odd_place: bool,
    /// Built here (cargo, Xcode, CortexTerm and its plugins): unsigned by nature, noted, not alerted.
    built_here: bool,
    /// The signer's team id, empty when none.
    team: String,
}

pub struct Watch {
    state: State,
    saved: Instant,
    /// The day (Unix ms / DAY) the byte counts were last written: they are written once a day,
    /// so their history is a sample a day, not one per save.
    bytes_day: u64,
    /// (pid, proto, local port, remote, remote port) -> bytes out at the last sample.
    flows: HashMap<(u32, String, u16, IpAddr, u16), u64>,
    /// The same flows' (bytes out, bytes in) at the last sample.
    bytes: HashMap<(u32, String, u16, IpAddr, u16), (u64, u64)>,
    /// (trust key, remote) -> when new connections to it began (Unix ms).
    starts: HashMap<(String, IpAddr), VecDeque<u64>>,
    procs: HashMap<u32, ProcInfo>,
    /// Last sample's PID/start/executable, required before interpreting a counter delta.
    incarnations: HashMap<u32, (u64, String)>,
    /// pid -> (the terminal command it belongs to, last seen).
    runs: HashMap<u32, (String, u64)>,
    /// Gone from the first sample: flows already open then are not "new".
    first: bool,
}

impl Watch {
    pub async fn load() -> Result<Self, String> {
        let state = load_state().await?;
        Ok(Watch {
            state,
            saved: Instant::now(),
            bytes_day: 0,
            flows: HashMap::new(),
            bytes: HashMap::new(),
            starts: HashMap::new(),
            procs: HashMap::new(),
            incarnations: HashMap::new(),
            runs: HashMap::new(),
            first: true,
        })
    }

    fn learning(&self) -> bool {
        now_ms().saturating_sub(self.state.since) < LEARN
    }

    fn info(&mut self, pid: u32, name: &str, snapshot: &HashMap<u32, &crate::procs::Entry>) -> ProcInfo {
        if let Some(info) = self.procs.get(&pid) {
            return info.clone();
        }
        let entry = snapshot.get(&pid);
        let exe = entry.map(|e| e.exe.clone()).unwrap_or_default();
        #[cfg(target_os = "macos")]
        let exe = if exe.is_empty() { libproc::libproc::proc_pid::pidpath(pid as i32).unwrap_or_default() } else { exe };
        let name = entry.map(|e| e.proc.name.clone()).unwrap_or_else(|| name.to_owned());
        let app = entry.map(|e| e.proc.app.clone()).unwrap_or_else(|| crate::procs::app_of(&exe, &name, pid, u32::MAX));
        let command = entry.map(|e| e.proc.command.clone()).unwrap_or_default();
        let system = ["/System/", "/usr/libexec/", "/usr/sbin/", "/usr/bin/", "/sbin/", "/bin/"].iter().any(|p| exe.starts_with(p));
        let signature = if (system || exe.is_empty()) && cfg!(target_os = "macos") {
            crate::codesign::Signature { status: "signed".into(), apple: true, identifier: name.clone(), ..Default::default() }
        } else {
            crate::codesign::check(std::path::Path::new(&exe))
        };
        let unsigned = signature.unsigned();
        let adhoc = signature.status == "adhoc";
        // Trust follows the signer and the signing identifier (the bundle id), not the path.
        let id = if signature.identifier.is_empty() { app.clone() } else { signature.identifier.clone() };
        let key = if exe.is_empty() {
            format!("name:{name}")
        } else if signature.apple && cfg!(target_os = "macos") {
            format!("apple:{id}")
        } else if signature.status == "signed" && !signature.team_id.is_empty() {
            format!("team:{}:{id}", signature.team_id)
        } else {
            format!("path:{exe}")
        };
        let home = crate::util::home().display().to_string();
        let odd_place = ["/tmp/", "/private/tmp/", "/var/tmp/", "/private/var/tmp/", "/Users/Shared/"].iter().any(|p| exe.starts_with(p))
            || exe.starts_with("/private/var/folders/") && !exe.contains(".app/")
            || exe.starts_with(&format!("{home}/Downloads/"));
        // This app's own bundle (CortexTerm and the plugins it ships), and the Cortex apps' homes.
        let own = std::env::current_exe().ok().map(|p| p.display().to_string()).and_then(|p| p.find(".app/").map(|end| p[..end + 5].to_owned()));
        let built_here = ["/target/debug/", "/target/release/", "/DerivedData/", "/.cortexterm/", "/.cortexcode/", "/.cargo/bin/", "/node_modules/"]
            .iter()
            .any(|p| exe.contains(p))
            || own.is_some_and(|own| exe.starts_with(&own));
        let quarantined = !exe.is_empty() && !system && crate::host::quarantined(std::path::Path::new(&exe));
        let team = signature.team_id.clone();
        let info = ProcInfo { name, app, exe, command, key, unsigned, adhoc, quarantined, odd_place, built_here, team };
        self.procs.insert(pid, info.clone());
        info
    }

    /// The terminal command a process (or one of its parents) belongs to.
    fn run_of(&self, pid: u32, parents: &HashMap<u32, u32>) -> Option<String> {
        let mut pid = pid;
        for _ in 0..16 {
            if let Some((command, _)) = self.runs.get(&pid) {
                return Some(command.clone());
            }
            pid = *parents.get(&pid).filter(|p| **p > 1)?;
        }
        None
    }

    /// One sample: what it found to alert on. `runs` are the pids of live terminal commands.
    pub fn tick(&mut self, snapshot: &Snapshot, runs: Vec<(u32, String)>) -> Vec<Candidate> {
        let now = now_ms();
        for (pid, command) in runs {
            self.runs.insert(pid, (command, now));
        }
        self.runs.retain(|_, (_, seen)| now.saturating_sub(*seen) < HOUR);
        let sample = match sample() {
            Ok(sample) => sample,
            Err(error) => {
                tracing::info!("network watcher: {error}");
                crate::protection::health("connections", "App connections", "unavailable", "The connection sample failed; network activity during this interval may be missing.");
                return Vec::new();
            }
        };
        crate::protection::health("connections", "App connections", "active", "Connection metadata sampled every 15 seconds. Short-lived connections can be missed; this is not packet capture.");
        let tables = feeds::tables();
        let by_pid: HashMap<u32, &crate::procs::Entry> = snapshot.entries.iter().map(|e| (e.proc.pid, e)).collect();
        let incarnations: HashMap<u32, (u64, String)> = snapshot.entries.iter().filter(|e| e.proc.started > 0 && !e.exe.is_empty()).map(|e| (e.proc.pid, (e.proc.started, e.exe.clone()))).collect();
        let parents: HashMap<u32, u32> = snapshot.entries.iter().map(|e| (e.proc.pid, e.proc.ppid)).collect();
        self.procs.retain(|pid, _| sample.contains_key(pid) && self.incarnations.get(pid) == incarnations.get(pid));
        let learning = self.learning();
        let hour = now / HOUR;
        let mut found = Vec::new();
        let mut flows_now = HashMap::new();
        let mut evidence_count = 0usize;

        for (pid, (name, flows)) in &sample {
            let same_incarnation = incarnations.contains_key(pid) && self.incarnations.get(pid) == incarnations.get(pid);
            let online: Vec<&Flow> = flows.iter().filter(|f| public(f.remote)).collect();
            // Bytes sent to the internet since the last sample (a new flow counts whole).
            let mut uploaded = 0;
            for f in flows.iter().filter(|f| f.counted) {
                let key = (*pid, f.proto.clone(), f.local_port, f.remote, f.remote_port);
                let before = same_incarnation.then(|| self.flows.get(&key).copied()).flatten();
                flows_now.insert(key, f.bytes_out);
                if public(f.remote) {
                    uploaded += match before {
                        Some(before) => f.bytes_out.saturating_sub(before),
                        None if self.first => 0,
                        None => f.bytes_out,
                    };
                }
            }
            if online.is_empty() {
                continue;
            }
            let info = self.info(*pid, name, &by_pid);
            let run = self.run_of(*pid, &parents);
            let who = who(&info, *pid, run.as_deref());
            let profile = self.state.apps.entry(info.key.clone()).or_insert_with(|| Profile { name: info.app.clone(), hour, ..Default::default() });
            roll(profile, hour, &info.key);
            profile.hour_bytes += uploaded;
            profile.name = info.app.clone();
            if !info.exe.is_empty() && profile.exe != info.exe {
                profile.exe = info.exe.clone();
                profile.dirty = true;
            }
            profile.signed = if cfg!(target_os = "linux") { "unknown" } else if info.adhoc { "adhoc" } else if info.unsigned { "unsigned" } else { "signed" }.into();
            profile.team = info.team.clone();
            // Bytes per network since the last sample.
            for f in flows.iter().filter(|f| public(f.remote)) {
                let key = (*pid, f.proto.clone(), f.local_port, f.remote, f.remote_port);
                let (out_before, in_before) = self.bytes.get(&key).copied().unwrap_or(if self.first { (f.bytes_out, f.bytes_in) } else { (0, 0) });
                let owner = tables.owner(f.remote);
                if owner.asn == 0 {
                    continue;
                }
                let usage = profile.nets.entry(owner.asn).or_insert_with(|| NetUse { owner: owner.name.clone(), country: owner.country.clone(), ..Default::default() });
                if f.counted {
                    usage.bytes_out += f.bytes_out.saturating_sub(out_before);
                    usage.bytes_in += f.bytes_in.saturating_sub(in_before);
                }
                usage.ports.insert(f.remote_port);
                profile.dirty = true;
            }

            // An unsigned, ad-hoc or quarantined program, or one in a temporary folder, online.
            if (info.unsigned || info.quarantined || info.odd_place) && !info.exe.is_empty() && self.state.unsigned_seen.insert(info.exe.clone()) {
                flag_online(&info);
                let what = if info.adhoc {
                    "a program with no real signature (ad-hoc)"
                } else if info.unsigned {
                    "an unsigned program"
                } else if info.quarantined {
                    "a downloaded program never approved in Finder"
                } else {
                    "a program"
                };
                let place = if info.odd_place { format!(" running from {}", crate::util::tilde(std::path::Path::new(&info.exe))) } else { String::new() };
                let first = online[0];
                let text = format!(
                    "{who}, {what}{place}, is talking to the internet: {} on port {}, {}.",
                    first.remote,
                    first.remote_port,
                    tables.owner(first.remote).label()
                );
                // Unsigned or unapproved and in a temporary or download folder: the best single sign.
                // Plainly unsigned elsewhere alerts after the learning week; ad-hoc builds are noted.
                let strong = info.odd_place && (info.unsigned || info.quarantined);
                let plain = info.unsigned && !info.adhoc && !info.built_here && !learning;
                if strong || plain {
                    found.push(candidate(format!("network:unsigned:{}", info.exe), if strong { "high" } else { "warn" }, text, *pid, &info.exe));
                } else {
                    // The digest names the program, not the pid, so a restart does not repeat it.
                    let path = crate::util::tilde(std::path::Path::new(&info.exe));
                    note(&info.app, "network", "low", format!("{} ({path}), {what}, went online: {}.", info.app, tables.owner(first.remote).label()));
                }
            }

            // A stealer's drop named on the command line.
            let exempt = MESSENGERS_AND_BROWSERS.contains(&info.app.as_str()) && !info.unsigned;
            if !exempt {
                let command = info.command.to_ascii_lowercase();
                if let Some(drop) = DROPS.iter().find(|d| command.contains(*d)) {
                    found.push(candidate(
                        format!("network:drop:{}:{drop}", info.key),
                        "high",
                        format!("{who} names {drop} on its command line and is online; that is where stolen data is often sent."),
                        *pid,
                        &info.exe,
                    ));
                }
            }

            let mut seen_remote = HashSet::new();
            for flow in online {
                let owner = tables.owner(flow.remote);
                let to = format!("{} on port {}, {}", flow.remote, flow.remote_port, owner.label());
                let new_flow = !self.first && !self.flows.contains_key(&(*pid, flow.proto.clone(), flow.local_port, flow.remote, flow.remote_port));

                if flow.counted && same_incarnation && evidence_count < 256 {
                    let previous = self.flows.get(&(*pid, flow.proto.clone(), flow.local_port, flow.remote, flow.remote_port)).copied();
                    if let Some(delta) = previous.and_then(|before| flow.bytes_out.checked_sub(before)).filter(|delta| *delta > 0) {
                        if let Some(entry) = by_pid.get(pid) {
                            crate::protection::observe(cc_protocol::contracts::system::SecurityObservation {
                                at: now, source: "connection watcher".into(), kind: "outbound".into(), severity: "info".into(),
                                summary: format!("{} sent {delta} bytes to {} on port {} between two samples of the same process and flow. Payload, purpose and connection initiation were not observed.", info.app, flow.remote, flow.remote_port),
                                rule: "network.sent_bytes".into(), subject: format!("process:{}:{}", pid, entry.proc.started),
                                pid: Some(*pid), process_started: Some(entry.proc.started), parent_pid: Some(entry.proc.ppid), executable: Some(info.exe.clone()), remote: Some(flow.remote.to_string()), port: Some(flow.remote_port), count: 1, ..Default::default()
                            });
                            evidence_count += 1;
                        }
                    }
                }

                if (new_flow || self.first) && evidence_count < 256 {
                    if let Some(entry) = by_pid.get(pid).filter(|e| e.proc.started > 0 && !info.exe.is_empty()) {
                        crate::protection::observe(cc_protocol::contracts::system::SecurityObservation {
                            at: now, source: "connection watcher".into(), kind: "connection".into(), severity: "info".into(),
                            summary: format!("{} has a {} connection with {} on port {}. Observed byte counters: {} received, {} sent; connection initiation and payload are not observed.", info.app, flow.proto, flow.remote, flow.remote_port, flow.bytes_in, flow.bytes_out),
                            subject: format!("process:{}:{}", pid, entry.proc.started), pid: Some(*pid), process_started: Some(entry.proc.started),
                            parent_pid: Some(entry.proc.ppid), executable: Some(info.exe.clone()), remote: Some(flow.remote.to_string()), port: Some(flow.remote_port), count: 1, ..Default::default()
                        });
                        evidence_count += 1;
                    }
                }

                if let Some(list) = tables.threat(flow.remote) {
                    // Cloud addresses change hands, so a listed one there is noted, not alerted.
                    if MAJOR.contains(&owner.asn) {
                        note(&info.app, "network", "medium", format!("{} connected to {to}, a cloud address that is on {list}.", info.app));
                    } else {
                        found.push(candidate(
                            format!("network:threat:{}:{}", info.key, flow.remote),
                            "high",
                            format!("{who} connected to {to}, an address on {list}."),
                            *pid,
                            &info.exe,
                        ));
                    }
                }
                if TELEGRAM.contains(&owner.asn) && !exempt {
                    found.push(candidate(
                        format!("network:telegram:{}", info.key),
                        "high",
                        format!("{who} is talking to Telegram's servers ({to}). It is not Telegram, and stealers send what they take there."),
                        *pid,
                        &info.exe,
                    ));
                }
                if ODD_PORTS.contains(&flow.remote_port) {
                    note(&info.app, "network", "medium", format!("{} connected out to port {} at {}, a port used by backdoors and IRC bots.", info.app, flow.remote_port, owner.label()));
                }
                if [25, 465, 587].contains(&flow.remote_port) && !MAIL_APPS.contains(&info.app.as_str()) && !info.key.starts_with("apple:") {
                    note(&info.app, "network", "medium", format!("{} sent mail directly (port {}) to {}; it is not a mail app.", info.app, flow.remote_port, owner.label()));
                }

                // Firsts: learnt quietly the first week, then noted in the digest.
                let profile = self.state.apps.entry(info.key.clone()).or_default();
                let new_asn = owner.asn != 0 && profile.asns.insert(owner.asn);
                let new_country = !owner.country.is_empty() && profile.countries.insert(owner.country.clone());
                if new_country && !learning {
                    note(&info.app, "network", "low", format!("{} talked to a server in {} for the first time: {}.", info.app, owner.country, owner.label()));
                } else if new_asn && !learning {
                    note(&info.app, "network", "info", format!("{} talked to {} for the first time.", info.app, owner.label()));
                }
                if profile.ports.len() < 64 {
                    profile.ports.insert(flow.remote_port);
                }

                // The rhythm of new connections to one address.
                if new_flow && seen_remote.insert(flow.remote) {
                    let starts = self.starts.entry((info.key.clone(), flow.remote)).or_default();
                    starts.push_back(now);
                    while starts.len() > 48 {
                        starts.pop_front();
                    }
                    if let Some((every, score)) = beacon(starts)
                        && !MAJOR.contains(&owner.asn)
                    {
                        starts.clear();
                        let every = crate::util::duration_text(every);
                        // Signed software and what was built here check in on a timer all the time;
                        // a beacon alerts when nothing vouches for the program.
                        let unvouched = (info.unsigned && !info.built_here) || info.quarantined || info.odd_place;
                        if unvouched {
                            found.push(candidate(
                                format!("network:beacon:{}:{}", info.key, flow.remote),
                                "warn",
                                format!("{who} opens a new connection to {to} like clockwork, about every {every} (regularity {:.0}%); malware calls home this way.", score * 100.0),
                                *pid,
                                &info.exe,
                            ));
                        } else {
                            note(&info.app, "network", "info", format!("{} checks in with {} about every {every}, a timer like most signed software has.", info.app, owner.label()));
                        }
                    }
                }
            }
        }

        // Upload far above the app's own normal.
        if !learning {
            for (key, profile) in &self.state.apps {
                if profile.hours.len() < 48 || profile.hour != hour {
                    continue;
                }
                let threshold = upload_threshold(&profile.hours);
                if profile.hour_bytes > threshold {
                    found.push(Candidate {
                        key: format!("network:upload:{key}:{hour}"),
                        alert: Alert {
                            kind: "network".into(),
                            severity: "high".into(),
                            text: format!(
                                "{} has uploaded {} MB to the internet this hour, far above its usual (the line is {} MB an hour). Data may be leaving this Mac.",
                                profile.name,
                                profile.hour_bytes / MB,
                                threshold / MB
                            ),
                            actions: vec!["show".into()],
                            ..Default::default()
                        },
                    });
                }
            }
        }

        self.flows = flows_now;
        self.incarnations = incarnations;
        self.bytes = sample
            .iter()
            .flat_map(|(pid, (_, flows))| flows.iter().map(move |f| ((*pid, f.proto.clone(), f.local_port, f.remote, f.remote_port), (f.bytes_out, f.bytes_in))))
            .collect();
        self.first = false;
        let stale = now.saturating_sub(DAY);
        self.starts.retain(|_, starts| starts.back().is_some_and(|at| *at > stale));
        if self.starts.len() > 2000 {
            self.starts.clear();
        }
        if self.saved.elapsed() >= Duration::from_secs(600) {
            self.save();
        }
        found
    }

    /// Write what changed: each program's networks, with the bytes so far once a day.
    pub fn save(&mut self) {
        // Each program hangs from this Mac; until its root node is known nothing is written (the
        // programs stay dirty and go with a later save).
        let Some(machine) = graph::machine() else {
            self.saved = Instant::now();
            tracing::info!("network watcher: this Mac's root node is not known yet; what it learnt is written later");
            return;
        };
        let hour = now_ms() / HOUR;
        let day = now_ms() / DAY;
        let bytes = day != self.bytes_day;
        self.bytes_day = day;
        for (key, profile) in self.state.apps.iter_mut() {
            roll(profile, hour, key);
        }
        if self.state.unsigned_seen.len() > 2000 {
            self.state.unsigned_seen.clear();
        }
        let mut batch = Batch::new();
        for (trust, profile) in self.state.apps.iter_mut().filter(|(_, p)| (p.dirty || bytes) && !p.exe.is_empty() && !p.nets.is_empty()) {
            profile.dirty = false;
            batch.units.push(program_unit(trust, profile, bytes, &machine));
        }
        graph::put(batch);
        self.saved = Instant::now();
    }
}

/// A program online (`ON` this Mac), its signer and the networks it talks to; `bytes`: with the
/// bytes so far.
fn program_unit(trust: &str, profile: &Profile, bytes: bool, machine: &cc_protocol::contracts::memory::GraphRef) -> graph::Unit {
    let mut unit = graph::Unit::default();
    let me = r("Binary", profile.exe.clone());
    unit.node("Binary", profile.exe.clone()).p("trust", trust).p("app", profile.name.clone()).ps("signed", &profile.signed).ps("team", &profile.team);
    unit.edge(me.clone(), "ON", machine.clone());
    if !profile.team.is_empty() {
        unit.node("Signer", profile.team.clone());
        unit.edge(me.clone(), "SIGNED_BY", r("Signer", profile.team.clone()));
    }
    for (asn, usage) in &profile.nets {
        let net = r("Network", asn.to_string());
        unit.node("Network", asn.to_string()).ps("owner", &usage.owner).ps("country", &usage.country);
        let ports: Vec<u64> = usage.ports.iter().take(64).map(|p| u64::from(*p)).collect();
        let edge = unit.edge(me.clone(), "CONNECTED", net);
        edge.p("ports", ports);
        if bytes {
            edge.t("bytes_out", usage.bytes_out).t("bytes_in", usage.bytes_in);
        }
    }
    unit
}

/// An unsigned (or unapproved, or oddly placed) program went online for the first time.
fn flag_online(info: &ProcInfo) {
    if !graph::ready() {
        return;
    }
    let mut batch = Batch::new();
    let unit = batch.unit();
    unit.node("Binary", info.exe.clone()).p("flagged_online", true).p("trust", info.key.clone()).p("app", info.app.clone());
    // It needs an edge until its networks are written: its folder.
    let folder = graph::folder(unit, std::path::Path::new(&info.exe).parent().unwrap_or(std::path::Path::new("/")));
    unit.edge(r("Binary", info.exe.clone()), "IN", folder);
    graph::put(batch);
}

/// "Slack (pid 812)", with the terminal command when one started it.
fn who(info: &ProcInfo, pid: u32, run: Option<&str>) -> String {
    let name = if info.app == info.name { info.name.clone() } else { format!("{} ({})", info.app, info.name) };
    match run {
        Some(command) => format!("{name}, pid {pid}, started by the command `{}` you ran in the terminal,", shorten(command, 80)),
        None => format!("{name} (pid {pid})"),
    }
}

fn candidate(key: String, severity: &str, text: String, pid: u32, exe: &str) -> Candidate {
    Candidate {
        key,
        alert: Alert {
            kind: "network".into(),
            severity: severity.into(),
            text,
            pid: Some(pid),
            path: (!exe.is_empty()).then(|| exe.to_owned()),
            actions: vec!["show".into(), "kill".into()],
            ..Default::default()
        },
    }
}

/// Close the hours that passed (an idle hour uploads nothing); an hour with uploads goes to the
/// `net.upload` stream.
fn roll(profile: &mut Profile, hour: u64, trust: &str) {
    if profile.hour == 0 {
        profile.hour = hour;
    }
    if hour <= profile.hour {
        return;
    }
    if profile.hour_bytes > 0 {
        graph::append(UPLOAD_TOPIC, vec![json!({"trust": trust, "hour": profile.hour, "bytes": profile.hour_bytes})], 14);
    }
    profile.hours.push_back(profile.hour_bytes);
    for _ in 0..(hour - profile.hour - 1).min(HOURS as u64) {
        profile.hours.push_back(0);
    }
    while profile.hours.len() > HOURS {
        profile.hours.pop_front();
    }
    profile.hour = hour;
    profile.hour_bytes = 0;
}

fn median(values: &mut [u64]) -> u64 {
    if values.is_empty() {
        return 0;
    }
    values.sort_unstable();
    values[values.len() / 2]
}

/// Far above normal: more than 50 MB and more than the median plus ten median deviations.
fn upload_threshold(hours: &VecDeque<u64>) -> u64 {
    let mut values: Vec<u64> = hours.iter().copied().collect();
    let mid = median(&mut values);
    let mut deviations: Vec<u64> = values.iter().map(|v| v.abs_diff(mid)).collect();
    let mad = median(&mut deviations);
    (50 * MB).max(mid + 10 * mad)
}

/// RITA-style: at least 24 connection starts whose gaps are regular (small median deviation
/// against the median gap) and at least 30 s apart. The typical gap and the score (0..1).
fn beacon(starts: &VecDeque<u64>) -> Option<(u64, f64)> {
    if starts.len() < 24 {
        return None;
    }
    let mut gaps: Vec<u64> = starts.iter().zip(starts.iter().skip(1)).map(|(a, b)| b - a).collect();
    let mid = median(&mut gaps);
    if mid < 30_000 {
        return None;
    }
    let mut deviations: Vec<u64> = gaps.iter().map(|g| g.abs_diff(mid)).collect();
    let mad = median(&mut deviations);
    let score = 1.0 - (mad as f64 / mid as f64).min(1.0);
    (score >= 0.85).then_some((mid, score))
}

/// The watcher's loop: a sample every 15 s, the feeds refreshed when due (checked hourly), and
/// this Mac's network (gateway, DHCP, DNS, IPv6 router, Wi-Fi) compared every minute.
pub async fn run(
    snapshot: impl Fn() -> Arc<Snapshot> + Send + Sync + 'static,
    runs: impl Fn() -> Vec<(u32, String)> + Send + Sync + 'static,
    fire: impl Fn(Candidate) + Send + Sync + 'static,
) {
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        return;
    }
    // The lists are kept in the graph: their age is known once it is loaded.
    while !graph::wait_ready(Duration::from_secs(3600)).await {}
    tokio::spawn(async {
        loop {
            if feeds::refresh().await {
                // Rebuild the tables off the async threads.
                let _ = tokio::task::spawn_blocking(feeds::tables).await;
            }
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    });
    let mut watch = loop {
        match Watch::load().await {
            Ok(watch) => break Some(watch),
            Err(error) => {
                tracing::info!("network watcher: cannot load what it learnt: {error}");
                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        }
    };
    #[cfg(target_os = "linux")]
    note("Network", "network", "info", "Linux socket monitoring checks destinations and connection patterns; per-connection byte counts are unavailable from procfs, so upload-volume detection is unavailable.".into());
    let mut every = tokio::time::interval(Duration::from_secs(15));
    every.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut last_net: Option<Instant> = None;
    loop {
        every.tick().await;
        let Some(mut w) = watch.take() else { return };
        let (snap, live_runs) = (snapshot(), runs());
        let net_due = last_net.is_none_or(|t| t.elapsed() >= Duration::from_secs(60));
        if net_due {
            last_net = Some(Instant::now());
        }
        let Ok((w, mut found)) = tokio::task::spawn_blocking(move || {
            let found = w.tick(&snap, live_runs);
            (w, found)
        })
        .await
        else {
            watch = Watch::load().await.ok();
            continue;
        };
        watch = Some(w);
        if net_due && let Ok(changes) = tokio::task::spawn_blocking(crate::netsec::network_changes).await {
            for change in changes {
                if change.alert {
                    found.push(Candidate {
                        key: format!("lan:{}", change.text),
                        alert: Alert {
                            kind: "lan".into(),
                            severity: if change.severity == "high" { "high" } else { "warn" }.into(),
                            text: change.text.clone(),
                            actions: vec!["show".into()],
                            ..Default::default()
                        },
                    });
                }
                note("Network", "lan", &change.severity, change.text);
            }
        }
        for candidate in found {
            fire(candidate);
        }
    }
}

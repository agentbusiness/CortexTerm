//! Free threat-intelligence and lookup lists, kept as cache files (`docs`), each refreshed on its
//! own cadence and used from the stored copy when offline.
//!
//! - hard evidence about an address: Spamhaus DROP (IPv4 and IPv6 ranges) and ASN-DROP (whole
//!   networks, matched through the owner table), daily;
//! - hard evidence about an address, a domain or a URL: abuse.ch ThreatFox (botnet and stealer
//!   C2, payload hosts) and URLhaus (malware download URLs). Both need the free abuse.ch Auth-Key
//!   the person saves for MalwareBazaar; without it they are reported as disabled, never as clean;
//! - context only, never an alert by itself: the Tor exit list (anonymity, not malice) and
//!   Hagezi's threat-feed IPs (a large, low-confidence aggregate);
//! - who owns an IP: iptoasn.com's public-domain table (owner network, ASN and country);
//! - who made a network card: Wireshark's `manuf` (vendor by MAC prefix), read only by the sweep.
//!
//! Lookups are binary searches over sorted ranges and hash lookups held in memory (about 10 MB
//! for the ASN table).

use crate::docs;
use crate::util::now_ms;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const HOUR: u64 = 3_600_000;
const SPAMHAUS_TERMS: &str = "Spamhaus DROP data, (c) The Spamhaus Project SLU, used under its terms (https://www.spamhaus.org/drop/terms/).";

struct Feed {
    /// What the user reads: "Spamhaus DROP".
    name: &'static str,
    url: &'static str,
    file: &'static str,
    /// Downloaded again once the stored copy is this old.
    hours: u64,
    /// A match is hard evidence (else context only).
    hard: bool,
    /// The finding `source` a match is reported under.
    source: &'static str,
}

/// Address lists (ranges or single addresses), hard ones first.
const LISTS: &[Feed] = &[
    Feed { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v4.json", file: "drop_v4.json", hours: 24, hard: true, source: "spamhaus-drop" },
    Feed { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v6.json", file: "drop_v6.json", hours: 24, hard: true, source: "spamhaus-drop" },
    Feed { name: "the Tor exit list", url: "https://check.torproject.org/torbulkexitlist", file: "tor_exits.txt", hours: 24, hard: false, source: "tor-exit" },
    Feed { name: "Hagezi threat feed", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt", file: "hagezi_tif_ips.txt", hours: 24, hard: false, source: "hagezi" },
];
/// Networks (ASNs) Spamhaus says are run by criminals.
const ASN_DROP: Feed = Feed { name: "Spamhaus ASN-DROP", url: "https://www.spamhaus.org/drop/asndrop.json", file: "asndrop.json", hours: 24, hard: true, source: "spamhaus-asndrop" };
/// abuse.ch: the API's last 7 days, merged into the stored copy and kept 30 days.
const THREATFOX: Feed = Feed { name: "abuse.ch ThreatFox", url: "https://threatfox-api.abuse.ch/api/v1/", file: "threatfox-iocs.json", hours: 6, hard: true, source: "threatfox" };
/// abuse.ch: URLs of the last 30 days; the key is part of the path, so the URL is never logged.
const URLHAUS: Feed = Feed { name: "abuse.ch URLhaus", url: "https://urlhaus-api.abuse.ch/v2/files/exports/", file: "urlhaus-urls.json", hours: 12, hard: true, source: "urlhaus" };
const ASN: Feed = Feed { name: "iptoasn", url: "https://iptoasn.com/data/ip2asn-combined.tsv.gz", file: "ip2asn-combined.tsv.gz", hours: 168, hard: false, source: "" };
const OUI: Feed = Feed { name: "Wireshark manuf", url: "https://www.wireshark.org/download/automated/data/manuf", file: "manuf", hours: 168, hard: false, source: "" };
/// abuse.ch entries kept this long after they were first seen.
const IOC_DAYS: i64 = 30;
/// ThreatFox entries below this confidence are left out.
const IOC_CONFIDENCE: u64 = 75;

/// Lists files earlier versions kept that are no longer used (dead or redundant).
const RETIRED: [&str; 2] = ["feodo.txt", "firehol_level1.netset"];

/// Why the last abuse.ch download failed, by file (shown in health until one succeeds).
static FAILED: Mutex<Option<HashMap<&'static str, String>>> = Mutex::new(None);

fn failed(file: &'static str, why: Option<String>) {
    let mut slot = FAILED.lock().unwrap_or_else(|p| p.into_inner());
    let map = slot.get_or_insert_with(HashMap::new);
    match why {
        Some(why) => map.insert(file, why),
        None => map.remove(file),
    };
}

fn age_ms(feed: &Feed) -> Option<u64> {
    docs::fetched(feed.file).map(|at| now_ms().saturating_sub(at))
}

fn due(feed: &Feed) -> bool {
    age_ms(feed).is_none_or(|age| age >= feed.hours * HOUR)
}

/// Cached threat coverage is visible even offline; an old or missing list is never called clean,
/// and an abuse.ch list without a key is disabled.
pub fn protection_health() -> Vec<cc_protocol::contracts::system::ProtectionSensor> {
    let abusech = crate::keys::status().abusech;
    let failures = FAILED.lock().unwrap_or_else(|p| p.into_inner()).clone().unwrap_or_default();
    let mut sensors = lists_health(abusech, &failures);
    if cfg!(target_os = "macos") {
        let fetched = docs::fetched(crate::malware::FORGE_FILE);
        let release = docs::get_blocking(crate::malware::FORGE_FILE).and_then(|doc| crate::malware::forge_release(&String::from_utf8_lossy(&doc.bytes)).map(str::to_owned));
        let fresh = fetched.is_some_and(|at| now_ms().saturating_sub(at) <= 14 * 24 * HOUR);
        sensors.push(cc_protocol::contracts::system::ProtectionSensor {
            id: format!("feed:{}", crate::malware::FORGE_FILE),
            label: "YARA Forge macOS rules".into(),
            state: if fresh { "active" } else if fetched.is_some() { "degraded" } else { "unavailable" }.into(),
            detail: match (fetched, release) {
                (Some(at), Some(tag)) => format!("Release {tag}, checked {} days ago; the malware scan uses its macOS rules next to XProtect's and CortexTerm's own.", now_ms().saturating_sub(at) / (24 * HOUR)),
                _ => "Not downloaded yet; the malware scan uses XProtect's and CortexTerm's own rules only.".into(),
            },
            last_at: fetched.unwrap_or(0),
            dropped: 0,
        });
    }
    sensors
}

fn lists_health(abusech: bool, failures: &HashMap<&'static str, String>) -> Vec<cc_protocol::contracts::system::ProtectionSensor> {
    LISTS.iter().chain([&ASN_DROP, &THREATFOX, &URLHAUS]).map(|feed| {
        let fetched = docs::fetched(feed.file);
        let fresh = fetched.is_some_and(|at| now_ms().saturating_sub(at) <= feed.hours * HOUR * 2);
        let keyed = feed.file == THREATFOX.file || feed.file == URLHAUS.file;
        let role = if feed.hard { "A match is hard evidence about the address." } else { "Context only: a match is noted, never alerted by itself." };
        let terms = if feed.source.starts_with("spamhaus") { format!(" {SPAMHAUS_TERMS}") } else { String::new() };
        let (state, detail) = if keyed && !abusech {
            ("disabled", "Disabled: no abuse.ch Auth-Key is saved, so this source gives no coverage. This is not a clean result.".to_owned())
        } else {
            let state = if keyed && failures.contains_key(feed.file) { "degraded" } else if fresh { "active" } else if fetched.is_some() { "degraded" } else { "unavailable" };
            let failure = failures.get(feed.file).map(|why| format!(" The last download failed: {why}.")).unwrap_or_default();
            let detail = match fetched {
                Some(at) => format!(
                    "Cached list fetched {} hours ago. {}{failure}{terms}",
                    now_ms().saturating_sub(at) / HOUR,
                    if fresh { role } else { "Refresh is overdue; matches may be incomplete." }
                ),
                None => format!("No cached copy is available; this source provides no coverage yet.{failure}{terms}"),
            };
            (state, detail)
        };
        cc_protocol::contracts::system::ProtectionSensor {
            id: format!("feed:{}", feed.file),
            label: feed.name.into(),
            state: state.into(),
            detail,
            last_at: fetched.unwrap_or(0),
            dropped: 0,
        }
    }).collect()
}

/// Download the lists that are due, and YARA Forge's rules when they are. True when a list the
/// tables are built from changed. Failures keep the stored copy.
pub async fn refresh() -> bool {
    let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(90)).user_agent("CortexTerm").build() else { return false };
    for retired in RETIRED {
        docs::remove(retired);
    }
    let mut changed = false;
    for feed in LISTS.iter().chain([&ASN_DROP, &ASN, &OUI]) {
        if !due(feed) {
            continue;
        }
        match client.get(feed.url).send().await {
            Ok(response) if response.status().is_success() => match response.bytes().await {
                Ok(bytes) if bytes.len() > 64 => {
                    docs::put(feed.file, bytes.to_vec(), now_ms());
                    changed = true;
                }
                _ => tracing::info!("feed {}: empty download", feed.name),
            },
            Ok(response) => tracing::info!("feed {}: {} answered {}", feed.name, feed.url, response.status()),
            Err(error) => tracing::info!("feed {}: {error}", feed.name),
        }
    }
    let key = tokio::task::spawn_blocking(|| crate::keys::get("abusech")).await.ok().flatten();
    if let Some(key) = key {
        for feed in [&THREATFOX, &URLHAUS] {
            if !due(feed) {
                continue;
            }
            let result = if feed.file == THREATFOX.file { threatfox(&client, &key).await } else { urlhaus(&client, &key).await };
            match result {
                Ok(bytes) => {
                    docs::put(feed.file, bytes, now_ms());
                    failed(feed.file, None);
                    changed = true;
                }
                Err(why) => {
                    tracing::info!("feed {}: {why}", feed.name);
                    failed(feed.file, Some(why));
                }
            }
        }
    }
    #[cfg(target_os = "macos")]
    crate::malware::refresh_forge(&client).await;
    if changed && let Ok(mut slot) = TABLES.write() {
        *slot = None;
    }
    changed
}

// --- abuse.ch indicators.

/// One kept indicator: `k` ip | domain | url, the value, the port (ip only), the malware family or
/// threat, and the day it was first seen (`YYYY-MM-DD`).
#[derive(Serialize, Deserialize, Clone)]
struct Ioc {
    k: String,
    v: String,
    #[serde(default)]
    p: u16,
    #[serde(default)]
    m: String,
    d: String,
}

/// A URL as compared: scheme and host lowercased, no fragment, no trailing slash.
pub fn normal_url(url: &str) -> String {
    let url = url.trim().split('#').next().unwrap_or("");
    let Some((scheme, rest)) = url.split_once("://") else { return url.trim_end_matches('/').to_ascii_lowercase() };
    let (host, path) = rest.split_once('/').map(|(h, p)| (h, format!("/{p}"))).unwrap_or((rest, String::new()));
    format!("{}://{}{}", scheme.to_ascii_lowercase(), host.to_ascii_lowercase(), path).trim_end_matches('/').to_owned()
}

/// The host of a URL, lowercased, without port or credentials.
pub fn url_host(url: &str) -> Option<String> {
    let rest = url.trim().split_once("://")?.1;
    let host = rest.split(['/', '?', '#']).next()?.rsplit('@').next()?;
    let host = if host.starts_with('[') { host.split(']').next()?.trim_start_matches('[') } else { host.split(':').next()? };
    (!host.is_empty()).then(|| host.trim_end_matches('.').to_ascii_lowercase())
}

/// ThreatFox's last 7 days (confidence 75 or more), merged with the stored copy; 30 days kept.
async fn threatfox(client: &reqwest::Client, key: &str) -> Result<Vec<u8>, String> {
    let response = client
        .post(THREATFOX.url)
        .header("Auth-Key", key)
        .header("content-type", "application/json")
        .body(r#"{"query":"get_iocs","days":7}"#)
        .send()
        .await
        .map_err(|e| format!("ThreatFox could not be reached ({})", if e.is_timeout() { "timed out" } else { "network error" }))?;
    let status = response.status().as_u16();
    if status == 401 || status == 403 {
        return Err(format!("ThreatFox refused the abuse.ch key (HTTP {status})"));
    }
    if status != 200 {
        return Err(format!("ThreatFox answered HTTP {status}"));
    }
    let bytes = response.bytes().await.map_err(|_| "the ThreatFox answer broke off".to_owned())?;
    let answer: Value = serde_json::from_slice(&bytes).map_err(|_| "ThreatFox sent something unreadable".to_owned())?;
    let rows = match answer["query_status"].as_str() {
        Some("ok") => answer["data"].as_array().cloned().unwrap_or_default(),
        Some("no_result") => Vec::new(),
        other => return Err(format!("ThreatFox answered {}", other.unwrap_or("without a status"))),
    };
    let mut fresh = Vec::new();
    for row in &rows {
        if row["confidence_level"].as_u64().unwrap_or(0) < IOC_CONFIDENCE {
            continue;
        }
        let (Some(kind), Some(value)) = (row["ioc_type"].as_str(), row["ioc"].as_str()) else { continue };
        let family = row["malware_printable"].as_str().filter(|m| !m.is_empty() && *m != "Unknown malware").or(row["threat_type"].as_str()).unwrap_or("").to_owned();
        let day: String = row["first_seen"].as_str().unwrap_or("").chars().take(10).collect();
        let ioc = match kind {
            "ip:port" => {
                let Some((host, port)) = value.rsplit_once(':') else { continue };
                let Ok(ip) = host.trim_matches(['[', ']']).parse::<IpAddr>() else { continue };
                Ioc { k: "ip".into(), v: ip.to_string(), p: port.parse().unwrap_or(0), m: family, d: day }
            }
            "domain" => Ioc { k: "domain".into(), v: value.trim().trim_end_matches('.').to_ascii_lowercase(), p: 0, m: family, d: day },
            "url" => Ioc { k: "url".into(), v: normal_url(value), p: 0, m: family, d: day },
            _ => continue,
        };
        fresh.push(ioc);
    }
    let old: Vec<Ioc> = docs::get(THREATFOX.file).await.and_then(|doc| serde_json::from_slice(&doc.bytes).ok()).unwrap_or_default();
    let today = crate::inventory::today();
    let mut seen = HashSet::new();
    let kept: Vec<Ioc> = fresh
        .into_iter()
        .chain(old)
        .filter(|ioc| crate::inventory::days(&ioc.d).is_none_or(|day| today - day <= IOC_DAYS))
        .filter(|ioc| seen.insert((ioc.k.clone(), ioc.v.clone(), ioc.p)))
        .collect();
    serde_json::to_vec(&kept).map_err(|e| e.to_string())
}

/// URLhaus's URLs of the last 30 days (`recent.csv`), kept as URL, threat and day.
async fn urlhaus(client: &reqwest::Client, key: &str) -> Result<Vec<u8>, String> {
    if !key.chars().all(|c| c.is_ascii_alphanumeric()) {
        return Err("the saved abuse.ch key has characters a key cannot have".into());
    }
    let response = client
        .get(format!("{}{key}/recent.csv", URLHAUS.url))
        .send()
        .await
        .map_err(|e| format!("URLhaus could not be reached ({})", if e.is_timeout() { "timed out" } else { "network error" }))?;
    let status = response.status().as_u16();
    if status == 401 || status == 403 {
        return Err(format!("URLhaus refused the abuse.ch key (HTTP {status})"));
    }
    if status != 200 {
        return Err(format!("URLhaus answered HTTP {status}"));
    }
    let bytes = response.bytes().await.map_err(|_| "the URLhaus answer broke off".to_owned())?;
    let text = String::from_utf8_lossy(&bytes);
    let mut kept = Vec::new();
    // "id","dateadded","url","url_status","last_online","threat","tags","urlhaus_link","reporter"
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<&str> = line.trim_matches('"').split("\",\"").collect();
        if fields.len() < 7 || !fields[2].contains("://") {
            continue;
        }
        let tags = fields[6].replace(',', ", ");
        let what = if tags.is_empty() { fields[5].to_owned() } else { format!("{} ({tags})", fields[5]) };
        kept.push(Ioc { k: "url".into(), v: normal_url(&fields[2].replace("\"\"", "\"")), p: 0, m: what, d: fields[1].chars().take(10).collect() });
    }
    if kept.is_empty() {
        return Err("URLhaus sent no readable rows".into());
    }
    serde_json::to_vec(&kept).map_err(|e| e.to_string())
}

// --- Addresses as numbers and ranges.

/// An address as one number: IPv4 as its IPv4-mapped IPv6 form.
pub fn number(ip: IpAddr) -> u128 {
    match ip {
        IpAddr::V4(v4) => u128::from(v4.to_ipv6_mapped()),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// `1.2.3.0/24`, `2001:db8::/32` or a lone address, as an inclusive range.
fn range_of(text: &str) -> Option<(u128, u128)> {
    let (addr, prefix) = match text.split_once('/') {
        Some((addr, prefix)) => (addr, Some(prefix.parse::<u32>().ok()?)),
        None => (text, None),
    };
    let ip: IpAddr = addr.trim().parse().ok()?;
    let bits = match (ip, prefix) {
        (_, None) => 128,
        (IpAddr::V4(_), Some(p)) if p <= 32 => 96 + p,
        (IpAddr::V6(_), Some(p)) if p <= 128 => p,
        _ => return None,
    };
    let start = number(ip);
    let host = if bits >= 128 { 0 } else { u128::MAX >> bits };
    Some((start & !host, start | host))
}

/// Sorted, merged ranges.
#[derive(Default)]
struct Ranges(Vec<(u128, u128)>);

impl Ranges {
    fn build(mut list: Vec<(u128, u128)>) -> Self {
        list.sort_unstable();
        let mut merged: Vec<(u128, u128)> = Vec::with_capacity(list.len());
        for (start, end) in list {
            match merged.last_mut() {
                Some(last) if start <= last.1.saturating_add(1) => last.1 = last.1.max(end),
                _ => merged.push((start, end)),
            }
        }
        Ranges(merged)
    }

    fn contains(&self, n: u128) -> bool {
        let i = self.0.partition_point(|(start, _)| *start <= n);
        i > 0 && self.0[i - 1].1 >= n
    }
}

/// The owner of an address.
#[derive(Debug, Clone, Default)]
pub struct Owner {
    pub asn: u32,
    /// Two letters, empty when unknown.
    pub country: String,
    /// "CLOUDFLARENET", shortened to its first word when it is long.
    pub name: String,
}

impl Owner {
    /// "Cloudflare (AS13335, US)".
    pub fn label(&self) -> String {
        if self.asn == 0 {
            return "an unknown network".into();
        }
        let country = if self.country.is_empty() { String::new() } else { format!(", {}", self.country) };
        format!("{} (AS{}{country})", self.name, self.asn)
    }
}

/// A list an address, domain or URL is on.
#[derive(Debug, Clone)]
pub struct Hit {
    /// What the user reads: "Spamhaus DROP".
    pub list: &'static str,
    /// The finding `source` and alert wording use this: `spamhaus-drop`, `threatfox` …
    pub source: &'static str,
    /// Hard evidence (DROP, ASN-DROP, ThreatFox, URLhaus); else context only (Tor, Hagezi).
    pub hard: bool,
    /// The malware family or threat when the list names one ("AMOS, port 443"), else empty.
    pub what: String,
}

impl Hit {
    /// "abuse.ch ThreatFox (AMOS, port 443)".
    pub fn label(&self) -> String {
        if self.what.is_empty() { self.list.to_owned() } else { format!("{} ({})", self.list, self.what) }
    }
}

pub struct Tables {
    lists: Vec<(&'static Feed, Ranges)>,
    asn_drop: HashSet<u32>,
    /// ThreatFox addresses: ip -> [(port, family)].
    ioc_ips: HashMap<IpAddr, Vec<(u16, String)>>,
    /// ThreatFox domains: domain -> family.
    ioc_domains: HashMap<String, String>,
    /// ThreatFox and URLhaus URLs: normalised URL -> (feed, family or threat).
    ioc_urls: HashMap<String, (&'static Feed, String)>,
    v4: Vec<(u32, u32, u32)>,
    v6: Vec<(u64, u64, u32)>,
    /// asn -> (country, owner name).
    owners: HashMap<u32, ([u8; 2], Box<str>)>,
    /// Lists with no cached copy yet.
    pub missing: Vec<&'static str>,
}

static TABLES: RwLock<Option<Arc<Tables>>> = RwLock::new(None);
static LOADING: Mutex<()> = Mutex::new(());

/// The tables from the stored lists (blocking on the first call and after a refresh: about a
/// second; call it from a blocking thread).
pub fn tables() -> Arc<Tables> {
    if let Some(tables) = TABLES.read().ok().and_then(|slot| slot.clone()) {
        return tables;
    }
    let _one = LOADING.lock();
    if let Some(tables) = TABLES.read().ok().and_then(|slot| slot.clone()) {
        return tables;
    }
    let started = std::time::Instant::now();
    let tables = Arc::new(load());
    tracing::info!("threat and network-owner tables read in {} ms ({} missing)", started.elapsed().as_millis(), tables.missing.len());
    // Before the graph is loaded the lists' index is not read: nothing is kept, the next call reads.
    if crate::graph::ready()
        && let Ok(mut slot) = TABLES.write()
    {
        *slot = Some(tables.clone());
    }
    tables
}

fn load() -> Tables {
    let mut missing = Vec::new();
    let mut lists: Vec<(&'static Feed, Vec<(u128, u128)>)> = Vec::new();
    for feed in LISTS {
        let Some(doc) = docs::get_blocking(feed.file) else {
            if !missing.contains(&feed.name) {
                missing.push(feed.name);
            }
            continue;
        };
        let text = String::from_utf8_lossy(&doc.bytes);
        let mut list = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            // Spamhaus: one JSON object a line (the last one is metadata, with no `cidr`).
            let token = if line.starts_with('{') {
                match serde_json::from_str::<Value>(line).ok().and_then(|v| v["cidr"].as_str().map(str::to_owned)) {
                    Some(cidr) => cidr,
                    None => continue,
                }
            } else {
                line.split([' ', '\t', ';']).next().unwrap_or("").to_owned()
            };
            if let Some(range) = range_of(&token) {
                list.push(range);
            }
        }
        match lists.iter_mut().find(|(known, _)| known.name == feed.name) {
            Some((_, existing)) => existing.extend(list),
            None => lists.push((feed, list)),
        }
    }
    let lists = lists.into_iter().map(|(feed, list)| (feed, Ranges::build(list))).collect();

    let mut asn_drop = HashSet::new();
    match docs::get_blocking(ASN_DROP.file) {
        Some(doc) => {
            for line in String::from_utf8_lossy(&doc.bytes).lines() {
                if let Some(asn) = serde_json::from_str::<Value>(line).ok().and_then(|v| v["asn"].as_u64()) {
                    asn_drop.insert(asn as u32);
                }
            }
        }
        None => missing.push(ASN_DROP.name),
    }

    let (mut ioc_ips, mut ioc_domains, mut ioc_urls) = (HashMap::<IpAddr, Vec<(u16, String)>>::new(), HashMap::new(), HashMap::new());
    for feed in [&THREATFOX, &URLHAUS] {
        let Some(doc) = docs::get_blocking(feed.file) else {
            missing.push(feed.name);
            continue;
        };
        for ioc in serde_json::from_slice::<Vec<Ioc>>(&doc.bytes).unwrap_or_default() {
            match ioc.k.as_str() {
                "ip" => {
                    if let Ok(ip) = ioc.v.parse::<IpAddr>() {
                        ioc_ips.entry(ip).or_default().push((ioc.p, ioc.m));
                    }
                }
                "domain" => {
                    ioc_domains.insert(ioc.v, ioc.m);
                }
                "url" => {
                    ioc_urls.insert(ioc.v, (feed, ioc.m));
                }
                _ => {}
            }
        }
    }

    let (mut v4, mut v6, mut owners) = (Vec::new(), Vec::new(), HashMap::new());
    // Streamed: the unpacked table is about 35 MB of text.
    let asn = docs::get_blocking(ASN.file);
    let lines: Box<dyn Iterator<Item = String>> = match &asn {
        Some(doc) => Box::new(BufReader::new(flate2::read::GzDecoder::new(std::io::Cursor::new(doc.bytes.to_vec()))).lines().map_while(Result::ok)),
        None => {
            missing.push("the IP owner table (iptoasn)");
            Box::new(std::iter::empty())
        }
    };
    for line in lines {
        let mut fields = line.split('\t');
        let (Some(start), Some(end), Some(asn), Some(country), Some(name)) =
            (fields.next(), fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        let Ok(asn) = asn.parse::<u32>() else { continue };
        if asn == 0 {
            continue;
        }
        match (start.parse::<IpAddr>(), end.parse::<IpAddr>()) {
            (Ok(IpAddr::V4(s)), Ok(IpAddr::V4(e))) => v4.push((u32::from(s), u32::from(e), asn)),
            (Ok(IpAddr::V6(s)), Ok(IpAddr::V6(e))) => v6.push(((u128::from(s) >> 64) as u64, (u128::from(e) >> 64) as u64, asn)),
            _ => continue,
        }
        owners.entry(asn).or_insert_with(|| {
            let cc = country.as_bytes();
            let cc = if cc.len() == 2 { [cc[0], cc[1]] } else { [0, 0] };
            (cc, short_name(name).into_boxed_str())
        });
    }
    v4.sort_unstable();
    v6.sort_unstable();
    Tables { lists, asn_drop, ioc_ips, ioc_domains, ioc_urls, v4, v6, owners, missing }
}

/// "CLOUDFLARENET" -> "Cloudflare"-ish: the first word of the owner, without `-AS` tails.
fn short_name(name: &str) -> String {
    let well_known = [
        ("CLOUDFLARENET", "Cloudflare"),
        ("AMAZON-02", "Amazon"),
        ("AMAZON-AES", "Amazon"),
        ("GOOGLE", "Google"),
        ("GOOGLE-CLOUD-PLATFORM", "Google Cloud"),
        ("MICROSOFT-CORP-MSN-AS-BLOCK", "Microsoft"),
        ("APPLE-ENGINEERING", "Apple"),
        ("APPLE-AUSTIN", "Apple"),
        ("AKAMAI-AS", "Akamai"),
        ("AKAMAI-ASN1", "Akamai"),
        ("FASTLY", "Fastly"),
        ("FACEBOOK", "Meta"),
        ("GITHUB", "GitHub"),
        ("DIGITALOCEAN-ASN", "DigitalOcean"),
        ("HETZNER-AS", "Hetzner"),
        ("OVH", "OVH"),
    ];
    let first = name.split_whitespace().next().unwrap_or(name);
    if let Some((_, nice)) = well_known.iter().find(|(raw, _)| *raw == first) {
        return (*nice).to_owned();
    }
    let trimmed = first.trim_end_matches("-AS").trim_end_matches("-ASN").trim_end_matches("-NET");
    crate::util::shorten(trimmed, 32)
}

impl Tables {
    /// The first list the address is on, hard lists first (any port).
    pub fn threat(&self, ip: IpAddr) -> Option<&'static str> {
        self.hit(ip, None).map(|hit| hit.list)
    }

    /// What lists say about an address, and the port it was reached on when known: ThreatFox
    /// (hard when the port is the listed one or unknown), DROP, ASN-DROP, then the context lists.
    pub fn hit(&self, ip: IpAddr, port: Option<u16>) -> Option<Hit> {
        let mut context = None;
        if let Some(entries) = self.ioc_ips.get(&ip) {
            let same = entries.iter().find(|(p, _)| port.is_none_or(|port| *p == port || *p == 0));
            let (listed_port, family) = same.unwrap_or(&entries[0]);
            let what = match (family.is_empty(), *listed_port) {
                (true, 0) => String::new(),
                (true, p) => format!("port {p}"),
                (false, 0) => family.clone(),
                (false, p) => format!("{family}, port {p}"),
            };
            let hit = Hit { list: THREATFOX.name, source: THREATFOX.source, hard: same.is_some(), what };
            if hit.hard {
                return Some(hit);
            }
            context = Some(hit);
        }
        let n = number(ip);
        if let Some((feed, _)) = self.lists.iter().find(|(feed, ranges)| feed.hard && ranges.contains(n)) {
            return Some(Hit { list: feed.name, source: feed.source, hard: true, what: String::new() });
        }
        let owner = self.owner(ip);
        if owner.asn != 0 && self.asn_drop.contains(&owner.asn) {
            return Some(Hit { list: ASN_DROP.name, source: ASN_DROP.source, hard: true, what: format!("AS{} {}", owner.asn, owner.name) });
        }
        context.or_else(|| {
            self.lists.iter().find(|(feed, ranges)| !feed.hard && ranges.contains(n)).map(|(feed, _)| Hit { list: feed.name, source: feed.source, hard: false, what: String::new() })
        })
    }

    /// A ThreatFox domain the host is, or is under (`a.evil.example` matches `evil.example`; a
    /// listed subdomain never matches its parent).
    pub fn domain(&self, host: &str) -> Option<Hit> {
        let host = host.trim().trim_end_matches('.').to_ascii_lowercase();
        let mut name = host.as_str();
        loop {
            if let Some(family) = self.ioc_domains.get(name) {
                let what = if name == host { family.clone() } else { format!("{family}, listed as {name}") };
                return Some(Hit { list: THREATFOX.name, source: THREATFOX.source, hard: true, what });
            }
            match name.split_once('.') {
                Some((_, parent)) if parent.contains('.') => name = parent,
                _ => return None,
            }
        }
    }

    /// A URL on ThreatFox or URLhaus exactly, else its host on ThreatFox's domains.
    pub fn url(&self, url: &str) -> Option<Hit> {
        if let Some((feed, what)) = self.ioc_urls.get(&normal_url(url)) {
            return Some(Hit { list: feed.name, source: feed.source, hard: true, what: what.clone() });
        }
        let host = url_host(url)?;
        match host.parse::<IpAddr>() {
            Ok(ip) => self.hit(ip, None).filter(|hit| hit.source == THREATFOX.source),
            Err(_) => self.domain(&host),
        }
    }

    /// Whether any abuse.ch indicator is loaded (domain and URL matching is possible).
    pub fn has_indicators(&self) -> bool {
        !self.ioc_domains.is_empty() || !self.ioc_urls.is_empty()
    }

    /// Who a network (ASN) belongs to.
    pub fn asn_owner(&self, asn: u32) -> Owner {
        match self.owners.get(&asn) {
            Some((cc, name)) => Owner { asn, country: if cc[0] == 0 { String::new() } else { String::from_utf8_lossy(cc).into_owned() }, name: name.to_string() },
            None => Owner { asn, ..Default::default() },
        }
    }

    pub fn owner(&self, ip: IpAddr) -> Owner {
        let asn = match ip {
            IpAddr::V4(v4) => {
                let n = u32::from(v4);
                let i = self.v4.partition_point(|r| r.0 <= n);
                (i > 0 && self.v4[i - 1].1 >= n).then(|| self.v4[i - 1].2)
            }
            IpAddr::V6(v6) => {
                let n = (u128::from(v6) >> 64) as u64;
                let i = self.v6.partition_point(|r| r.0 <= n);
                (i > 0 && self.v6[i - 1].1 >= n).then(|| self.v6[i - 1].2)
            }
        };
        match asn {
            Some(asn) => self.asn_owner(asn),
            None => Owner::default(),
        }
    }
}

/// Vendor by the MAC's first three bytes, from the stored `manuf` (read on each call: the sweep
/// uses it once). Empty when there is no copy yet. Blocking.
pub fn vendors() -> HashMap<[u8; 3], String> {
    let text = docs::get_blocking(OUI.file).map(|doc| String::from_utf8_lossy(&doc.bytes).into_owned()).unwrap_or_default();
    let mut map = HashMap::new();
    for line in text.lines() {
        if line.starts_with('#') {
            continue;
        }
        let mut fields = line.split('\t').map(str::trim).filter(|f| !f.is_empty());
        let (Some(prefix), Some(short)) = (fields.next(), fields.next()) else { continue };
        // Only whole 24-bit prefixes (`00:00:0C`), not `/28` and `/36` blocks.
        let bytes: Vec<u8> = prefix.split(':').filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
        if bytes.len() != 3 || prefix.contains('/') {
            continue;
        }
        let long = fields.next().unwrap_or(short);
        map.insert([bytes[0], bytes[1], bytes[2]], crate::util::shorten(long, 40));
    }
    map
}

//! Free threat-intelligence and lookup lists, kept as documents in the graph (`docs`): refreshed
//! at most once a day (the larger tables once a week), used from the stored copy when offline.
//!
//! - threat lists (IPs and CIDRs): FireHOL level 1, abuse.ch Feodo Tracker, Spamhaus DROP, the Tor
//!   exit list and Hagezi's threat-feed IPs;
//! - who owns an IP: iptoasn.com's public-domain table (owner network, ASN and country);
//! - who made a network card: Wireshark's `manuf` (vendor by MAC prefix), read only by the sweep.
//!
//! Lookups are binary searches over sorted ranges held in memory (about 10 MB for the ASN table).

use crate::docs;
use crate::util::now_ms;
use std::collections::HashMap;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

const DAY: u64 = 24 * 3_600_000;

struct Feed {
    /// What the user reads: "FireHOL level 1".
    name: &'static str,
    url: &'static str,
    file: &'static str,
    days: u64,
}

/// Threat lists, in the order a hit is named.
const THREATS: &[Feed] = &[
    Feed { name: "abuse.ch Feodo Tracker (botnet servers)", url: "https://feodotracker.abuse.ch/downloads/ipblocklist.txt", file: "feodo.txt", days: 1 },
    Feed { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v4.json", file: "drop_v4.json", days: 1 },
    Feed { name: "Spamhaus DROP", url: "https://www.spamhaus.org/drop/drop_v6.json", file: "drop_v6.json", days: 1 },
    Feed { name: "FireHOL level 1", url: "https://iplists.firehol.org/files/firehol_level1.netset", file: "firehol_level1.netset", days: 1 },
    Feed { name: "Hagezi threat feed", url: "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/ips/tif.txt", file: "hagezi_tif_ips.txt", days: 1 },
    Feed { name: "the Tor exit list", url: "https://check.torproject.org/torbulkexitlist", file: "tor_exits.txt", days: 1 },
];
const ASN: Feed = Feed { name: "iptoasn", url: "https://iptoasn.com/data/ip2asn-combined.tsv.gz", file: "ip2asn-combined.tsv.gz", days: 7 };
const OUI: Feed = Feed { name: "Wireshark manuf", url: "https://www.wireshark.org/download/automated/data/manuf", file: "manuf", days: 7 };

fn age_ms(feed: &Feed) -> Option<u64> {
    docs::fetched(feed.file).map(|at| now_ms().saturating_sub(at))
}

/// Cached threat coverage is visible even offline; an old or missing feed is never called clean.
pub fn protection_health() -> Vec<cc_protocol::contracts::system::ProtectionSensor> {
    THREATS.iter().map(|feed| {
        let fetched = docs::fetched(feed.file);
        let fresh = fetched.is_some_and(|at| now_ms().saturating_sub(at) <= feed.days * DAY * 2);
        cc_protocol::contracts::system::ProtectionSensor {
            id: format!("feed:{}", feed.file), label: feed.name.into(),
            state: if fresh { "active" } else if fetched.is_some() { "degraded" } else { "unavailable" }.into(),
            detail: match fetched {
                Some(at) => format!("Cached threat list fetched {} hours ago. {}", now_ms().saturating_sub(at) / 3_600_000, if fresh { "Used for destination matches; a match does not identify the person behind an address." } else { "Refresh is overdue; matches may be incomplete." }),
                None => "No cached threat list is available; this source provides no coverage yet.".into(),
            },
            last_at: fetched.unwrap_or(0), dropped: 0,
        }
    }).collect()
}

/// The list's address, by document name.
pub fn url_of(name: &str) -> Option<&'static str> {
    THREATS.iter().chain([&ASN, &OUI]).find(|f| f.file == name).map(|f| f.url)
}

/// Download the lists that are missing or stale. True when one changed. Failures keep the
/// stored copy.
pub async fn refresh() -> bool {
    let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(90)).user_agent("CortexTerm").build() else { return false };
    let mut changed = false;
    for feed in THREATS.iter().chain([&ASN, &OUI]) {
        if age_ms(feed).is_some_and(|age| age < feed.days * DAY) {
            continue;
        }
        match client.get(feed.url).send().await {
            Ok(response) if response.status().is_success() => match response.bytes().await {
                Ok(bytes) if bytes.len() > 64 => {
                    docs::put(feed.file, feed.url, bytes.to_vec(), now_ms());
                    changed = true;
                }
                _ => tracing::info!("feed {}: empty download", feed.name),
            },
            Ok(response) => tracing::info!("feed {}: {} answered {}", feed.name, feed.url, response.status()),
            Err(error) => tracing::info!("feed {}: {error}", feed.name),
        }
    }
    if changed && let Ok(mut slot) = TABLES.write() {
        *slot = None;
    }
    changed
}

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

pub struct Tables {
    threats: Vec<(&'static str, Ranges)>,
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
    tracing::info!("threat and network-owner tables read from the graph in {} ms ({} missing)", started.elapsed().as_millis(), tables.missing.len());
    // Before the graph is loaded the lists cannot be read: nothing is kept, the next call reads.
    if crate::graph::ready()
        && let Ok(mut slot) = TABLES.write()
    {
        *slot = Some(tables.clone());
    }
    tables
}

fn load() -> Tables {
    let mut missing = Vec::new();
    let mut threats: Vec<(&'static str, Vec<(u128, u128)>)> = Vec::new();
    for feed in THREATS {
        let Some(doc) = docs::get_blocking(feed.file) else {
            missing.push(feed.name);
            continue;
        };
        let text = String::from_utf8_lossy(&doc.bytes);
        let mut list = Vec::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            // Spamhaus: one JSON object a line.
            let token = if line.starts_with('{') {
                match serde_json::from_str::<serde_json::Value>(line).ok().and_then(|v| v["cidr"].as_str().map(str::to_owned)) {
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
        match threats.iter_mut().find(|(name, _)| *name == feed.name) {
            Some((_, existing)) => existing.extend(list),
            None => threats.push((feed.name, list)),
        }
    }
    let threats = threats.into_iter().map(|(name, list)| (name, Ranges::build(list))).collect();

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
    Tables { threats, v4, v6, owners, missing }
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
    /// The first threat list the address is on.
    pub fn threat(&self, ip: IpAddr) -> Option<&'static str> {
        let n = number(ip);
        self.threats.iter().find(|(_, ranges)| ranges.contains(n)).map(|(name, _)| *name)
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
        let Some(asn) = asn else { return Owner::default() };
        match self.owners.get(&asn) {
            Some((cc, name)) => Owner {
                asn,
                country: if cc[0] == 0 { String::new() } else { String::from_utf8_lossy(cc).into_owned() },
                name: name.to_string(),
            },
            None => Owner { asn, ..Default::default() },
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

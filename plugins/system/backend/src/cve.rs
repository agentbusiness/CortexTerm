//! One advisory (CVE, GHSA or another OSV id) checked against this Mac. NVD, OSV and EPSS say
//! what it is and what it covers; CISA KEV and Apple's release notes (SOFA) come from the sweep's
//! kept feeds. Code compares the versions; nothing is run or changed. When nothing could be
//! compared the verdict is `unknown`, never `not-affected`.
//!
//! The advisory is kept in the graph (and reused for a day):
//! `(:Advisory {key: id, aliases, title, summary, published, modified, cvss_*, cwe, epss*,
//! epss_percentile, kev, ransomware, kev_added, fetched_ms, found, checked, skipped})-[:SEEN_ON]->(:Machine)`, what it covers as
//! `(:AdvisoryCpe)-[:OF]->(:Advisory)` and `(:AdvisoryRange)-[:OF]->(:AdvisoryPackage)-[:OF]->(:Advisory)`,
//! its references as `-[:CITES {tags}]->(:Reference {key: url})`. What it was compared with on this
//! Mac is `(:Advisory)-[:AFFECTS {verdict*, version, fixed_in, fix}]->(:App | :Formula | :Package | :OS)`.

use crate::graph::{self, Props, r};
use crate::inventory::{self, ElectronIndex, KevRow, Local, major, version_cmp};
use crate::sweep::{self, Package};
use crate::util::{local_time, now_ms, plural, shorten, tilde};
use cc_protocol::contracts::memory::GraphLayer;
use serde_json::json;
use std::sync::Mutex;
use cc_protocol::contracts::system::{CveAffects, CveMatch, CveReference, CveReport, Cvss, Epss, Kev};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use std::time::Duration;

const DAY_MS: u64 = 86_400_000;
const UPDATE: &str = "open x-apple.systempreferences:com.apple.Software-Update-Settings.extension";

/// What the advisory sources said, as cached.
#[derive(Serialize, Deserialize, Default, Clone)]
struct Advisory {
    at: u64,
    /// NVD or OSV knows it.
    found: bool,
    aliases: Vec<String>,
    title: String,
    summary: String,
    published: String,
    modified: String,
    cvss: Option<Cvss>,
    cwe: Vec<String>,
    references: Vec<CveReference>,
    cpes: Vec<Cpe>,
    packages: Vec<OsvPackage>,
    epss: Option<Epss>,
    checked: Vec<String>,
    skipped: Vec<String>,
}

/// One vulnerable CPE match from NVD (empty strings are absent bounds).
#[derive(Serialize, Deserialize, Default, Clone)]
struct Cpe {
    part: String,
    vendor: String,
    product: String,
    /// An exact version, or empty for any (`*`, `-`).
    version: String,
    start_incl: String,
    start_excl: String,
    end_incl: String,
    end_excl: String,
}

type Events = Vec<(String, String)>;

/// One affected package from OSV.
#[derive(Serialize, Deserialize, Default, Clone)]
struct OsvPackage {
    ecosystem: String,
    name: String,
    /// (SEMVER | ECOSYSTEM | GIT, [(introduced | fixed | last_affected | limit, version)])
    ranges: Vec<(String, Events)>,
    versions: Vec<String>,
}

/// `CVE-2024-3094`, `GHSA-qwgh-2vcv-g2f7`, `RUSTSEC-2024-0001` …, or why not.
fn normalise(raw: &str) -> Result<String, String> {
    let id = raw.trim();
    let upper = id.to_ascii_uppercase();
    let digits = |s: &str, min: usize| s.len() >= min && s.chars().all(|c| c.is_ascii_digit());
    let year_and = |rest: &str, min: usize| rest.split_once('-').is_some_and(|(y, n)| digits(y, 4) && y.len() == 4 && digits(n, min));
    if let Some(rest) = upper.strip_prefix("CVE-")
        && year_and(rest, 4)
    {
        return Ok(upper);
    }
    if let Some(rest) = upper.strip_prefix("GHSA-") {
        let rest = rest.to_ascii_lowercase();
        let parts: Vec<&str> = rest.split('-').collect();
        if parts.len() == 3 && parts.iter().all(|p| p.len() == 4 && p.chars().all(|c| c.is_ascii_alphanumeric())) {
            return Ok(format!("GHSA-{rest}"));
        }
    }
    for prefix in ["RUSTSEC-", "PYSEC-", "MAL-", "GO-"] {
        if let Some(rest) = upper.strip_prefix(prefix)
            && year_and(rest, 1)
        {
            return Ok(upper);
        }
    }
    Err(format!(
        "`{}` is not an advisory id: use CVE-YYYY-NNNN, GHSA-xxxx-xxxx-xxxx, RUSTSEC-YYYY-NNNN, PYSEC-YYYY-N, MAL-YYYY-N or GO-YYYY-N",
        shorten(id, 60)
    ))
}

/// The report for one advisory id.
pub async fn report(raw: &str) -> Result<CveReport, String> {
    let id = normalise(raw)?;
    let client = client()?;
    // What is on this Mac, while the advisory is looked up.
    let gathering = tokio::task::spawn_blocking(Mac::gather);
    let (advisory, feeds) = tokio::join!(advisory(&client, &id), Feeds::load(&client));
    let mac = match tokio::time::timeout(Duration::from_secs(90), gathering).await {
        Ok(Ok(mac)) => Some(mac),
        _ => None,
    };
    let report = assemble(id, &advisory, &feeds, mac.as_ref());
    let present = remember(mac.as_ref()).await;
    record(&report, &present);
    Ok(report)
}

/// What is on this Mac goes to the graph once, so each advisory can point at it; what a look no
/// longer finds (an uninstalled app or formula) is marked gone. The nodes written.
async fn remember(mac: Option<&Mac>) -> std::collections::HashSet<cc_protocol::contracts::memory::GraphRef> {
    let seen: graph::Batch = mac.map(Mac::graph).unwrap_or_default();
    let present = seen.refs();
    graph::put(seen);
    if mac.is_some() {
        let keys = |label: &str| present.iter().filter(|r| r.label == label).map(|r| r.key.clone()).collect();
        inventory::retire_unseen("App", &keys("App")).await;
        inventory::retire_unseen("Formula", &keys("Formula")).await;
        inventory::retire_gone_repos(&keys("Repo")).await;
    }
    present
}

/// What a look at this Mac said about an advisory: `(:Advisory)-[:AFFECTS]->` each thing on this
/// Mac it was compared with (`present`: the nodes written for this look), with the verdict.
pub fn record(report: &CveReport, present: &std::collections::HashSet<cc_protocol::contracts::memory::GraphRef>) {
    if graph::machine().is_none() {
        return;
    }
    let mut batch = graph::Batch::in_layer(GraphLayer::Knowledge);
    let unit = batch.unit();
    let me = r("Advisory", report.id.clone());
    let node = unit.node("Advisory", report.id.clone());
    node.p("kev", report.kev.is_some())
        .p("ransomware", report.kev.as_ref().is_some_and(|k| k.ransomware))
        .p("kev_added", report.kev.as_ref().map_or(serde_json::Value::Null, |k| k.added.clone().into()))
        .p("verdict_text", report.verdict_text.clone());
    let mut linked = 0;
    // One edge per thing: the matches come worst first (affected, unknown, fixed, not affected),
    // so a package affected in one project and fixed in another is affected.
    let mut done = std::collections::HashSet::new();
    for m in &report.matches {
        let Some((label, key)) = &m.about else { continue };
        let target = r(label, key.clone());
        if !present.contains(&target) || !done.insert(target.clone()) {
            continue;
        }
        linked += 1;
        unit.edge(me.clone(), "AFFECTS", target)
            .t("verdict", m.verdict.clone())
            .p("version", m.version.clone())
            .p("fixed_in", m.fixed_in.clone())
            .p("place", m.place.clone())
            .p("why", m.why.clone())
            .p("fix", m.fix.clone().map(serde_json::Value::String).unwrap_or(serde_json::Value::Null));
    }
    // An advisory nothing here was compared with keeps only what it is (written when fetched).
    if linked > 0 || stored_index(&report.id) {
        graph::put(batch);
    }
}

/// Advisories this process wrote or read (so a node exists to add to).
static WRITTEN: Mutex<Option<std::collections::HashSet<String>>> = Mutex::new(None);

fn stored_index(id: &str) -> bool {
    WRITTEN.lock().unwrap_or_else(|p| p.into_inner()).as_ref().is_some_and(|set| set.contains(id))
}

fn mark_stored(id: &str) {
    WRITTEN.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(Default::default).insert(id.to_owned());
}

fn client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .connect_timeout(Duration::from_secs(8))
        .user_agent("CortexTerm-security-check")
        .build()
        .map_err(|e| e.to_string())
}

/// What one look at this Mac and the feeds serves: several advisories checked in a row (the CVE
/// watch), each looked up a few seconds apart so NVD does not refuse them.
pub struct Batch {
    client: reqwest::Client,
    feeds: Feeds,
    mac: Option<Mac>,
    present: std::collections::HashSet<cc_protocol::contracts::memory::GraphRef>,
}

impl Batch {
    pub async fn new() -> Result<Batch, String> {
        let client = client()?;
        let gathering = tokio::task::spawn_blocking(Mac::gather);
        let feeds = Feeds::load(&client).await;
        let mac = match tokio::time::timeout(Duration::from_secs(90), gathering).await {
            Ok(Ok(mac)) => Some(mac),
            _ => None,
        };
        let present = remember(mac.as_ref()).await;
        Ok(Batch { client, feeds, mac, present })
    }

    /// Write what a report said about this Mac (`record`).
    pub fn record(&self, report: &CveReport) {
        record(report, &self.present);
    }

    /// The CISA known-exploited rows.
    pub fn kev(&self) -> impl Iterator<Item = &KevRow> {
        self.feeds.kev.values()
    }

    /// The CVEs fixed in Apple's releases newer than this Mac's macOS and Safari that Apple marks
    /// as actively exploited.
    pub fn apple_exploited(&self) -> Vec<String> {
        let Some(mac) = &self.mac else { return Vec::new() };
        let mut out = Vec::new();
        for (feed, installed) in [(&self.feeds.sofa, &mac.local.os), (&self.feeds.safari, &mac.local.safari)] {
            if installed.is_empty() {
                continue;
            }
            let Some(feed) = feed else { continue };
            for release in feed["OSVersions"].as_array().into_iter().chain(feed["AppVersions"].as_array()).flatten() {
                for update in release["SecurityReleases"].as_array().into_iter().flatten() {
                    let version = update["ProductVersion"].as_str().unwrap_or("");
                    if loose_cmp(version, installed) != Some(Ordering::Greater) {
                        continue;
                    }
                    let marked = update["CVEs"].as_object().into_iter().flatten().filter(|(_, d)| d["ActivelyExploited"] == true || d["InKEV"] == true).map(|(id, _)| id.as_str());
                    for id in update["ActivelyExploitedCVEs"].as_array().into_iter().flatten().filter_map(Value::as_str).chain(marked) {
                        if !out.iter().any(|o| o == id) {
                            out.push(id.to_owned());
                        }
                    }
                }
            }
        }
        out
    }

    /// Lowercase names of everything installed (apps, Homebrew, global tools, project packages):
    /// what a CISA row's product is first compared with, so only plausible advisories are looked up.
    pub fn names(&self) -> BTreeSet<String> {
        let Some(mac) = &self.mac else { return BTreeSet::new() };
        let mut names = BTreeSet::new();
        names.extend(mac.local.apps.iter().map(|a| a.name.to_lowercase()));
        names.extend(mac.formulae.iter().chain(&mac.casks).map(|(n, _)| n.to_lowercase()));
        names.extend(mac.tools.iter().map(|t| t.name.to_lowercase()));
        names.extend(mac.local.projects.iter().flat_map(|p| p.packages.iter().map(|(_, n, _)| n.to_lowercase())));
        names
    }

    /// The project and global packages as OSV queries: (ecosystem, name, version).
    pub fn packages(&self) -> Vec<(String, String, String)> {
        let Some(mac) = &self.mac else { return Vec::new() };
        let mut out: BTreeSet<(String, String, String)> = BTreeSet::new();
        out.extend(mac.tools.iter().map(|t| (t.ecosystem.to_owned(), t.name.clone(), t.version.clone())));
        out.extend(mac.local.projects.iter().flat_map(|p| p.packages.iter().map(|(e, n, v)| ((*e).to_owned(), n.clone(), v.clone()))));
        out.into_iter().collect()
    }

    pub fn client(&self) -> &reqwest::Client {
        &self.client
    }

    pub async fn report(&self, raw: &str) -> Result<CveReport, String> {
        let id = normalise(raw)?;
        let advisory = advisory(&self.client, &id).await;
        Ok(assemble(id, &advisory, &self.feeds, self.mac.as_ref()))
    }
}

fn assemble(id: String, advisory: &Advisory, feeds: &Feeds, mac: Option<&Mac>) -> CveReport {
    let mut report = CveReport {
        id: id.clone(),
        aliases: advisory.aliases.clone(),
        title: advisory.title.clone(),
        summary: advisory.summary.clone(),
        published: advisory.published.clone(),
        modified: advisory.modified.clone(),
        cvss: advisory.cvss.clone(),
        cwe: advisory.cwe.clone(),
        epss: advisory.epss.clone(),
        references: advisory.references.clone(),
        checked: advisory.checked.clone(),
        skipped: advisory.skipped.clone(),
        ..Default::default()
    };
    report.checked.extend(feeds.notes.checked.iter().cloned());
    report.skipped.extend(feeds.notes.skipped.iter().cloned());
    let cves: Vec<String> = std::iter::once(&id).chain(&advisory.aliases).filter(|a| a.starts_with("CVE-")).cloned().collect();
    report.kev = cves.iter().find_map(|c| feeds.kev.get(c)).map(|row| Kev {
        added: row.added.clone(),
        due: row.due.clone(),
        ransomware: row.ransomware,
        action: row.action.clone(),
    });

    // What the advisory covers, and what on this Mac it was compared with.
    let mut affects = Vec::new();
    let mut matches = Vec::new();
    let apple = apple(feeds, &cves, mac, &mut affects, &mut matches);
    if let Some(mac) = mac {
        report.checked.push(mac.summary());
        report.skipped.extend(mac.skipped.iter().cloned());
        packages(&advisory.packages, mac, &mut affects, &mut matches);
        cpes(&advisory.cpes, mac, feeds, apple, &mut affects, &mut matches);
    } else {
        report.skipped.push("this Mac's apps and packages: reading them took longer than 90 s".into());
        packages(&advisory.packages, &Mac::default(), &mut affects, &mut Vec::new());
        cpes(&advisory.cpes, &Mac::default(), feeds, apple, &mut affects, &mut Vec::new());
    }
    affects.truncate(20);
    let order = |v: &str| match v {
        "affected" => 0,
        "unknown" => 1,
        "fixed" => 2,
        _ => 3,
    };
    matches.sort_by_key(|m: &CveMatch| order(&m.verdict));
    matches.truncate(30);
    report.affects = affects;
    homebrew_reach(&mut matches);
    report.matches = matches;
    verdict(&mut report, advisory, mac.is_some());
    report
}

// ---------------------------------------------------------------------------------------------
// The advisory: NVD, OSV and EPSS, cached a day.

/// Advisories read this run, by id.
static CACHE: Mutex<Option<BTreeMap<String, Advisory>>> = Mutex::new(None);

async fn advisory(client: &reqwest::Client, id: &str) -> Advisory {
    let mut cached = CACHE.lock().unwrap_or_else(|p| p.into_inner()).as_ref().and_then(|c| c.get(id).cloned());
    if cached.is_none() {
        cached = stored(id).await;
        if cached.is_some() {
            mark_stored(id);
        }
    }
    if let Some(cached) = cached.as_ref().filter(|c| now_ms().saturating_sub(c.at) < DAY_MS) {
        let mut cached = cached.clone();
        cached.checked.push(format!("advisory data from {} (kept for a day)", local_time(cached.at)));
        return cached;
    }
    let fresh = fetch(client, id).await;
    // A lookup that failed is not kept; an older copy stands in for it.
    if fresh.skipped.is_empty() {
        keep(id, &fresh, cached.as_ref());
        return fresh;
    }
    match cached {
        Some(mut old) if !fresh.found || old.found => {
            old.checked.push(format!("advisory data from {} (the lookup failed now: {})", local_time(old.at), fresh.skipped.join("; ")));
            old
        }
        _ => fresh,
    }
}

/// Keep a fresh advisory: in RAM, and in the graph, where the CPEs, packages and ranges the older
/// copy had beyond the fresh one's are retired.
fn keep(id: &str, advisory: &Advisory, old: Option<&Advisory>) {
    CACHE.lock().unwrap_or_else(|p| p.into_inner()).get_or_insert_with(BTreeMap::new).insert(id.to_owned(), advisory.clone());
    if let Some(batch) = advisory_batch(id, advisory) {
        graph::put(batch);
        mark_stored(id);
        let Some(old) = old else { return };
        let mut gone: Vec<_> = (advisory.cpes.len()..old.cpes.len()).map(|n| r("AdvisoryCpe", format!("{id}#cpe{n}"))).collect();
        for (n, package) in old.packages.iter().enumerate() {
            let key = format!("{id}#pkg{n}");
            let kept = advisory.packages.get(n).map_or(0, |p| p.ranges.len());
            gone.extend((kept..package.ranges.len()).map(|j| r("AdvisoryRange", format!("{key}#{j}"))));
            if n >= advisory.packages.len() {
                gone.push(r("AdvisoryPackage", key));
            }
        }
        if !gone.is_empty() {
            graph::retire(gone, "not in the advisory any more");
        }
    }
}

/// An advisory as graph units (in the knowledge layer).
/// An advisory file an earlier version kept (`cve/<id>.json`), as graph units (`migrate`).
pub fn migrated_advisory(id: &str, bytes: &[u8]) -> Option<graph::Batch> {
    let advisory: Advisory = serde_json::from_slice(bytes).ok()?;
    advisory_batch(id, &advisory)
}

fn advisory_batch(id: &str, a: &Advisory) -> Option<graph::Batch> {
    graph::machine()?;
    let at = a.at;
    let mut batch = graph::Batch::in_layer(GraphLayer::Knowledge);
    let me = r("Advisory", id);
    let unit = batch.unit();
    let node = unit.node("Advisory", id);
    node.p("name", if a.title.is_empty() { id.to_owned() } else { format!("{id}: {}", shorten(&a.title, 160)) })
        .p("found", a.found)
        .pl("aliases", a.aliases.clone())
        .p("title", a.title.clone())
        .p("summary", a.summary.clone())
        .p("published", a.published.clone())
        .p("modified", a.modified.clone())
        .pl("cwe", a.cwe.clone())
        .p("fetched_ms", at)
        .pl("checked", a.checked.clone())
        .pl("skipped", a.skipped.clone())
        .p("cpes", a.cpes.len() as u64)
        .p("packages", a.packages.len() as u64);
    match &a.cvss {
        Some(c) => {
            node.p("cvss_version", c.version.clone()).p("cvss_score", c.score).p("cvss_severity", c.severity.clone()).p("cvss_vector", c.vector.clone());
        }
        None => {
            node.p("cvss_version", serde_json::Value::Null).p("cvss_score", serde_json::Value::Null);
        }
    }
    if let Some(e) = &a.epss {
        node.t("epss", e.score).p("epss_percentile", e.percentile);
    }
    // This Mac holds the advisory: its references, CPEs and packages are new with it, so they
    // cannot (memory refuses a group of new nodes that reaches nothing stored).
    unit.edge(me.clone(), "SEEN_ON", graph::machine()?);
    for (n, reference) in a.references.iter().enumerate() {
        unit.node("Reference", reference.url.clone());
        unit.edge(me.clone(), "CITES", r("Reference", reference.url.clone())).pl("tags", reference.tags.clone()).p("n", n as u64).p("fetched_ms", at);
    }
    for (n, cpe) in a.cpes.iter().enumerate() {
        let key = format!("{id}#cpe{n}");
        let unit = batch.unit();
        unit.node("AdvisoryCpe", key.clone())
            .p("n", n as u64)
            .p("fetched_ms", at)
            .p("part", cpe.part.clone())
            .p("vendor", cpe.vendor.clone())
            .p("product", cpe.product.clone())
            .p("version", cpe.version.clone())
            .p("start_incl", cpe.start_incl.clone())
            .p("start_excl", cpe.start_excl.clone())
            .p("end_incl", cpe.end_incl.clone())
            .p("end_excl", cpe.end_excl.clone());
        unit.edge(r("AdvisoryCpe", key), "OF", me.clone());
    }
    for (n, package) in a.packages.iter().enumerate() {
        let key = format!("{id}#pkg{n}");
        let unit = batch.unit();
        unit.node("AdvisoryPackage", key.clone()).p("n", n as u64).p("fetched_ms", at).p("ecosystem", package.ecosystem.clone()).p("name", package.name.clone()).pl("versions", package.versions.clone());
        unit.edge(r("AdvisoryPackage", key.clone()), "OF", me.clone());
        for (j, (kind, events)) in package.ranges.iter().enumerate() {
            let range = format!("{key}#{j}");
            unit.node("AdvisoryRange", range.clone())
                .p("n", j as u64)
                .p("fetched_ms", at)
                .p("type", kind.clone())
                .pl("events_kind", events.iter().map(|(k, _)| k.clone()).collect())
                .pl("events_version", events.iter().map(|(_, v)| v.clone()).collect());
            unit.edge(r("AdvisoryRange", range), "OF", r("AdvisoryPackage", key.clone()));
        }
    }
    Some(batch)
}

/// The advisory as kept in the graph, if it is.
async fn stored(id: &str) -> Option<Advisory> {
    let k = json!({"k": id});
    let rows = graph::query(
        "MATCH (a:Advisory {key: $k}) WHERE a.fetched_ms IS NOT NULL RETURN a.fetched_ms, a.found, a.aliases, a.title, a.summary, a.published, a.modified, \
         a.cwe, a.checked, a.skipped, a.cvss_version, a.cvss_score, a.cvss_severity, a.cvss_vector, a.epss, a.epss_percentile",
        k.clone(),
    )
    .await
    .ok()?;
    let row = rows.first()?;
    let at = graph::number(&row[0]);
    let mut a = Advisory {
        at,
        found: row[1].as_bool().unwrap_or(false),
        aliases: graph::texts(&row[2]),
        title: graph::text(&row[3]),
        summary: graph::text(&row[4]),
        published: graph::text(&row[5]),
        modified: graph::text(&row[6]),
        cwe: graph::texts(&row[7]),
        checked: graph::texts(&row[8]),
        skipped: graph::texts(&row[9]),
        cvss: row[11].as_f64().map(|score| Cvss { version: graph::text(&row[10]), score, severity: graph::text(&row[12]), vector: graph::text(&row[13]) }),
        epss: row[14].as_f64().map(|score| Epss { score, percentile: row[15].as_f64().unwrap_or(0.0) }),
        ..Default::default()
    };
    let at_k = json!({"k": id, "at": at});
    let refs = graph::query("MATCH (:Advisory {key: $k})-[c:CITES]->(x:Reference) WHERE c.fetched_ms = $at RETURN x.key, c.tags ORDER BY c.n", at_k.clone()).await.ok()?;
    a.references = refs.iter().map(|row| CveReference { url: graph::text(&row[0]), tags: graph::texts(&row[1]) }).collect();
    let cpes = graph::query_all(
        "MATCH (c:AdvisoryCpe)-[:OF]->(:Advisory {key: $k}) WHERE c.fetched_ms = $at RETURN c.part, c.vendor, c.product, c.version, c.start_incl, c.start_excl, c.end_incl, c.end_excl ORDER BY c.n",
        at_k.clone(),
    )
    .await
    .ok()?;
    a.cpes = cpes
        .iter()
        .map(|row| Cpe {
            part: graph::text(&row[0]),
            vendor: graph::text(&row[1]),
            product: graph::text(&row[2]),
            version: graph::text(&row[3]),
            start_incl: graph::text(&row[4]),
            start_excl: graph::text(&row[5]),
            end_incl: graph::text(&row[6]),
            end_excl: graph::text(&row[7]),
        })
        .collect();
    let packages = graph::query_all(
        "MATCH (p:AdvisoryPackage)-[:OF]->(:Advisory {key: $k}) WHERE p.fetched_ms = $at RETURN p.key, p.ecosystem, p.name, p.versions ORDER BY p.n",
        at_k.clone(),
    )
    .await
    .ok()?;
    let ranges = graph::query_all(
        "MATCH (x:AdvisoryRange)-[:OF]->(p:AdvisoryPackage)-[:OF]->(:Advisory {key: $k}) WHERE x.fetched_ms = $at RETURN p.key, x.type, x.events_kind, x.events_version ORDER BY p.key, x.n",
        at_k,
    )
    .await
    .ok()?;
    a.packages = packages
        .iter()
        .map(|row| {
            let key = graph::text(&row[0]);
            OsvPackage {
                ecosystem: graph::text(&row[1]),
                name: graph::text(&row[2]),
                versions: graph::texts(&row[3]),
                ranges: ranges
                    .iter()
                    .filter(|range| graph::text(&range[0]) == key)
                    .map(|range| (graph::text(&range[1]), graph::texts(&range[2]).into_iter().zip(graph::texts(&range[3])).collect()))
                    .collect(),
            }
        })
        .collect();
    Some(a)
}

async fn get_json(client: &reqwest::Client, url: String, what: &str) -> Result<Option<Value>, String> {
    let response = client.get(&url).send().await.map_err(|e| format!("{what}: {}", if e.is_timeout() { "no answer within 15 s".into() } else { e.to_string() }))?;
    let status = response.status().as_u16();
    if status == 404 {
        return Ok(None);
    }
    if matches!(status, 403 | 429 | 503) {
        return Err(format!("{what} is limiting requests (answered {status}); try again in a minute"));
    }
    if !response.status().is_success() {
        return Err(format!("{what} answered {status}"));
    }
    let bytes = response.bytes().await.map_err(|e| format!("{what}: {e}"))?;
    serde_json::from_slice(&bytes).map(Some).map_err(|_| format!("{what} sent something unreadable"))
}

async fn fetch(client: &reqwest::Client, id: &str) -> Advisory {
    let mut advisory = Advisory { at: now_ms(), ..Default::default() };
    let osv_url = |id: &str| format!("https://api.osv.dev/v1/vulns/{id}");
    let mut osv_records: Vec<Value> = Vec::new();
    let mut cve = id.starts_with("CVE-").then(|| id.to_owned());

    let first = if let Some(cve) = &cve {
        let (nvd, osv, epss) = tokio::join!(
            get_json(client, format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"), "NVD"),
            get_json(client, osv_url(cve), "OSV"),
            epss(client, cve)
        );
        read_nvd(&mut advisory, nvd);
        advisory.epss = epss;
        osv
    } else {
        get_json(client, osv_url(id), "OSV").await
    };
    match first {
        Ok(Some(record)) => {
            advisory.found = true;
            advisory.checked.push("OSV".into());
            osv_records.push(record);
        }
        Ok(None) => advisory.checked.push(format!("OSV (no record for {})", cve.as_deref().unwrap_or(id))),
        Err(error) => advisory.skipped.push(error),
    }
    // The same advisory under other ids; package advisories among them (a CVE's GHSA) add the
    // packages, and an OSV id's CVE is what NVD and EPSS know.
    let others: Vec<String> = osv_records
        .first()
        .map(|r| ["aliases", "related"].iter().flat_map(|k| r[*k].as_array().into_iter().flatten()).filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default();
    if let Some(record) = osv_records.first() {
        for alias in record["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            if alias != id && !advisory.aliases.iter().any(|a| a == alias) {
                advisory.aliases.push(alias.to_owned());
            }
        }
    }
    let package_ids: Vec<&String> =
        others.iter().filter(|o| ["GHSA-", "PYSEC-", "RUSTSEC-", "GO-", "MAL-"].iter().any(|p| o.starts_with(p))).take(3).collect();
    if !package_ids.is_empty() {
        let mut tasks = tokio::task::JoinSet::new();
        for other in package_ids {
            let (client, url) = (client.clone(), osv_url(other));
            tasks.spawn(async move { get_json(&client, url, "OSV").await });
        }
        while let Some(done) = tasks.join_next().await {
            if let Ok(Ok(Some(record))) = done {
                osv_records.push(record);
            }
        }
    }
    if cve.is_none() {
        cve = advisory.aliases.iter().find(|a| a.starts_with("CVE-")).cloned();
        if let Some(cve) = &cve {
            let (nvd, epss) = tokio::join!(
                get_json(client, format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"), "NVD"),
                epss(client, cve)
            );
            read_nvd(&mut advisory, nvd);
            advisory.epss = epss;
        }
    }
    for record in &osv_records {
        read_osv(&mut advisory, record);
    }
    if advisory.epss.is_some() {
        advisory.checked.push("EPSS".into());
    }
    advisory
}

async fn epss(client: &reqwest::Client, cve: &str) -> Option<Epss> {
    let answer = get_json(client, format!("https://api.first.org/data/v1/epss?cve={cve}"), "EPSS").await.ok()??;
    let row = answer["data"].as_array()?.first()?;
    let number = |key: &str| row[key].as_str().and_then(|s| s.parse::<f64>().ok());
    Some(Epss { score: number("epss")?, percentile: number("percentile").unwrap_or(0.0) })
}

fn date(text: &str) -> String {
    text.chars().take(10).collect()
}

fn read_nvd(advisory: &mut Advisory, answer: Result<Option<Value>, String>) {
    let cve = match answer {
        Ok(Some(answer)) => match answer["vulnerabilities"].as_array().and_then(|v| v.first()) {
            Some(item) => item["cve"].clone(),
            None => {
                advisory.checked.push("NVD (no record)".into());
                return;
            }
        },
        Ok(None) => {
            advisory.checked.push("NVD (no record)".into());
            return;
        }
        Err(error) => {
            advisory.skipped.push(error);
            return;
        }
    };
    advisory.found = true;
    advisory.checked.push("NVD".into());
    let description = cve["descriptions"].as_array().into_iter().flatten().find(|d| d["lang"] == "en").and_then(|d| d["value"].as_str()).unwrap_or("");
    advisory.summary = shorten(&description.split_whitespace().collect::<Vec<_>>().join(" "), 600);
    advisory.published = date(cve["published"].as_str().unwrap_or(""));
    advisory.modified = date(cve["lastModified"].as_str().unwrap_or(""));
    // CVSS: the newest version, the primary (NVD's own) score first.
    for (key, version) in [("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0")] {
        let Some(list) = cve["metrics"][key].as_array().filter(|l| !l.is_empty()) else { continue };
        let metric = list.iter().find(|m| m["type"] == "Primary").unwrap_or(&list[0]);
        let data = &metric["cvssData"];
        let Some(score) = data["baseScore"].as_f64() else { continue };
        let severity = data["baseSeverity"].as_str().or_else(|| metric["baseSeverity"].as_str()).unwrap_or("").to_ascii_uppercase();
        advisory.cvss = Some(Cvss {
            version: version.into(),
            score,
            severity: if severity.is_empty() { severity_of_score(score).into() } else { severity },
            vector: data["vectorString"].as_str().unwrap_or("").to_owned(),
        });
        break;
    }
    for weakness in cve["weaknesses"].as_array().into_iter().flatten() {
        for d in weakness["description"].as_array().into_iter().flatten() {
            if let Some(id) = d["value"].as_str().filter(|v| v.starts_with("CWE-"))
                && !advisory.cwe.iter().any(|c| c == id)
            {
                advisory.cwe.push(id.to_owned());
            }
        }
    }
    let rank = |tags: &[String]| {
        ["Vendor Advisory", "Patch", "Mitigation", "Release Notes", "Third Party Advisory"].iter().position(|t| tags.iter().any(|x| x == t)).unwrap_or(9)
    };
    let mut references: Vec<CveReference> = cve["references"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| {
            Some(CveReference {
                url: r["url"].as_str()?.to_owned(),
                tags: r["tags"].as_array().into_iter().flatten().filter_map(|t| t.as_str().map(str::to_owned)).collect(),
            })
        })
        .collect();
    references.sort_by_key(|r| rank(&r.tags));
    references.dedup_by(|a, b| a.url == b.url);
    references.truncate(8);
    advisory.references = references;
    // Vulnerable CPEs; a configuration that needs another platform than Apple's is left out.
    for config in cve["configurations"].as_array().into_iter().flatten() {
        let nodes: Vec<&Value> = config["nodes"].as_array().into_iter().flatten().collect();
        let platforms: Vec<&str> = nodes
            .iter()
            .filter(|n| n["cpeMatch"].as_array().is_some_and(|m| !m.is_empty() && m.iter().all(|c| c["vulnerable"] == false)))
            .flat_map(|n| n["cpeMatch"].as_array().into_iter().flatten().filter_map(|c| c["criteria"].as_str()))
            .collect();
        if config["operator"] == "AND" && !platforms.is_empty() && !platforms.iter().any(|p| p.contains(":apple:")) {
            continue;
        }
        for node in nodes {
            for m in node["cpeMatch"].as_array().into_iter().flatten().filter(|m| m["vulnerable"] == true) {
                let Some(criteria) = m["criteria"].as_str() else { continue };
                let fields: Vec<&str> = criteria.split(':').collect();
                if fields.len() < 6 {
                    continue;
                }
                let bound = |key: &str| m[key].as_str().unwrap_or("").to_owned();
                let version = if matches!(fields[5], "*" | "-") { String::new() } else { fields[5].replace('\\', "") };
                advisory.cpes.push(Cpe {
                    part: fields[2].to_owned(),
                    vendor: fields[3].replace('\\', ""),
                    product: fields[4].replace('\\', ""),
                    version,
                    start_incl: bound("versionStartIncluding"),
                    start_excl: bound("versionStartExcluding"),
                    end_incl: bound("versionEndIncluding"),
                    end_excl: bound("versionEndExcluding"),
                });
                if advisory.cpes.len() >= 400 {
                    return;
                }
            }
        }
    }
}

fn read_osv(advisory: &mut Advisory, record: &Value) {
    let text = |key: &str| record[key].as_str().unwrap_or("").trim().to_owned();
    if advisory.title.is_empty() {
        advisory.title = shorten(&text("summary"), 160);
    }
    if advisory.summary.is_empty() {
        advisory.summary = shorten(&prose(&text("details")), 600);
    }
    if advisory.published.is_empty() {
        advisory.published = date(&text("published"));
        advisory.modified = date(&text("modified"));
    }
    if advisory.cwe.is_empty() {
        advisory.cwe = record["database_specific"]["cwe_ids"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)).collect();
    }
    if advisory.cvss.is_none() {
        let vectors: Vec<&str> = record["severity"].as_array().into_iter().flatten().filter_map(|s| s["score"].as_str()).collect();
        let label = record["database_specific"]["severity"].as_str().unwrap_or("").to_ascii_uppercase();
        advisory.cvss = vectors
            .iter()
            .find_map(|v| cvss3(v).map(|score| Cvss { version: v[5..8].to_owned(), score, severity: severity_of_score(score).into(), vector: (*v).to_owned() }))
            .or_else(|| {
                (!label.is_empty()).then(|| Cvss {
                    version: String::new(),
                    score: 0.0,
                    severity: if label == "MODERATE" { "MEDIUM".into() } else { label.clone() },
                    vector: vectors.first().map(|v| (*v).to_owned()).unwrap_or_default(),
                })
            });
    }
    if advisory.references.is_empty() {
        let rank = |kind: &str| ["ADVISORY", "FIX", "PACKAGE", "REPORT", "WEB"].iter().position(|t| *t == kind).unwrap_or(9);
        let mut references: Vec<CveReference> = record["references"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|r| Some(CveReference { url: r["url"].as_str()?.to_owned(), tags: vec![r["type"].as_str().unwrap_or("WEB").to_owned()] }))
            .collect();
        references.sort_by_key(|r| rank(&r.tags[0]));
        references.truncate(8);
        advisory.references = references;
    }
    for affected in record["affected"].as_array().into_iter().flatten() {
        let (Some(ecosystem), Some(name)) = (affected["package"]["ecosystem"].as_str(), affected["package"]["name"].as_str()) else { continue };
        let ranges = affected["ranges"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| {
                let events = r["events"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|e| e.as_object()?.iter().next().and_then(|(k, v)| Some((k.clone(), v.as_str()?.to_owned()))))
                    .collect();
                (r["type"].as_str().unwrap_or("").to_owned(), events)
            })
            .collect();
        let versions: Vec<String> = affected["versions"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)).take(2000).collect();
        let package = OsvPackage { ecosystem: ecosystem.to_owned(), name: name.to_owned(), ranges, versions };
        if !advisory.packages.iter().any(|p| p.ecosystem == package.ecosystem && p.name == package.name && p.ranges == package.ranges) {
            advisory.packages.push(package);
        }
    }
}

/// The prose of an OSV `details` (Markdown): headings dropped, cut at the first code block.
fn prose(markdown: &str) -> String {
    let mut words = Vec::new();
    for line in markdown.lines() {
        let line = line.trim();
        if line.starts_with("```") {
            break;
        }
        if !line.starts_with('#') {
            words.extend(line.split_whitespace());
        }
    }
    words.join(" ")
}

fn severity_of_score(score: f64) -> &'static str {
    match score {
        s if s >= 9.0 => "CRITICAL",
        s if s >= 7.0 => "HIGH",
        s if s >= 4.0 => "MEDIUM",
        s if s > 0.0 => "LOW",
        _ => "NONE",
    }
}

/// The CVSS 3.x base score of a vector (`CVSS:3.1/AV:N/AC:L/…`).
fn cvss3(vector: &str) -> Option<f64> {
    let rest = vector.strip_prefix("CVSS:3.1/").or_else(|| vector.strip_prefix("CVSS:3.0/"))?;
    let metrics: BTreeMap<&str, &str> = rest.split('/').filter_map(|p| p.split_once(':')).collect();
    let changed = *metrics.get("S")? == "C";
    let av = match *metrics.get("AV")? { "N" => 0.85, "A" => 0.62, "L" => 0.55, "P" => 0.2, _ => return None };
    let ac = match *metrics.get("AC")? { "L" => 0.77, "H" => 0.44, _ => return None };
    let pr = match (*metrics.get("PR")?, changed) {
        ("N", _) => 0.85,
        ("L", false) => 0.62,
        ("L", true) => 0.68,
        ("H", false) => 0.27,
        ("H", true) => 0.5,
        _ => return None,
    };
    let ui = match *metrics.get("UI")? { "N" => 0.85, "R" => 0.62, _ => return None };
    let cia = |key: &str| match metrics.get(key).copied() {
        Some("H") => Some(0.56),
        Some("L") => Some(0.22),
        Some("N") => Some(0.0),
        _ => None,
    };
    let iss = 1.0 - (1.0 - cia("C")?) * (1.0 - cia("I")?) * (1.0 - cia("A")?);
    let impact = if changed { 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02f64).powi(15) } else { 6.42 * iss };
    let exploitability = 8.22 * av * ac * pr * ui;
    if impact <= 0.0 {
        return Some(0.0);
    }
    let raw = if changed { (1.08 * (impact + exploitability)).min(10.0) } else { (impact + exploitability).min(10.0) };
    // CVSS 3.1's round-up to one decimal.
    let whole = (raw * 100_000.0).round() as i64;
    Some(if whole % 10_000 == 0 { whole as f64 / 100_000.0 } else { ((whole / 10_000) + 1) as f64 / 10.0 })
}

// ---------------------------------------------------------------------------------------------
// The feeds the sweep keeps: CISA KEV, SOFA (macOS and Safari), Electron releases.

#[derive(Default)]
struct Feeds {
    kev: BTreeMap<String, KevRow>,
    sofa: Option<Value>,
    safari: Option<Value>,
    electron: Option<ElectronIndex>,
    notes: sweep::Part,
}

impl Feeds {
    async fn load(client: &reqwest::Client) -> Feeds {
        let load = async {
            tokio::join!(
                inventory::feed(client, inventory::KEV_FILE, inventory::KEV, inventory::keep_kev),
                inventory::feed(client, "sofa-macos.json", inventory::SOFA_MACOS, inventory::json_ok),
                inventory::feed(client, "sofa-safari.json", inventory::SOFA_SAFARI, inventory::json_ok),
                inventory::feed(client, "electron.json", inventory::ELECTRON, inventory::keep_electron),
            )
        };
        let (kev, sofa, safari, electron) = match tokio::time::timeout(Duration::from_secs(45), load).await {
            Ok(loaded) => loaded,
            Err(_) => {
                let late = || Err("no answer within 45 s".to_owned());
                let mut out = Vec::new();
                for name in [inventory::KEV_FILE, "sofa-macos.json", "sofa-safari.json", "electron.json"] {
                    out.push(inventory::cached_feed_async(name).await.map(|b| (b, Some(0))).ok_or(()).or_else(|_| late()));
                }
                let mut out = out.into_iter();
                let mut next = || out.next().unwrap_or_else(late);
                (next(), next(), next(), next())
            }
        };
        let mut feeds = Feeds::default();
        let mut take = |label: &str, result: Result<(Vec<u8>, Option<u64>), String>| match result {
            Ok((bytes, None)) => {
                feeds.notes.checked.push(label.to_owned());
                Some(bytes)
            }
            Ok((bytes, Some(age))) => {
                feeds.notes.checked.push(format!("{label} (offline: the copy from {} ago)", plural(age as usize, "day", "days")));
                Some(bytes)
            }
            Err(error) => {
                feeds.notes.skipped.push(format!("{label}: {error}, and no copy is cached"));
                None
            }
        };
        let kev = take("CISA KEV", kev);
        let sofa = take("SOFA macOS", sofa);
        let safari = take("SOFA Safari", safari);
        let electron = take("Electron releases", electron);
        feeds.kev = kev.and_then(|b| serde_json::from_slice::<Vec<KevRow>>(&b).ok()).unwrap_or_default().into_iter().map(|r| (r.id.clone(), r)).collect();
        feeds.sofa = sofa.and_then(|b| serde_json::from_slice(&b).ok());
        feeds.safari = safari.and_then(|b| serde_json::from_slice(&b).ok());
        feeds.electron = electron.and_then(|b| serde_json::from_slice(&b).ok());
        feeds
    }
}

// ---------------------------------------------------------------------------------------------
// This Mac.

#[derive(Default)]
struct Mac {
    local: Local,
    /// Homebrew formulae and casks: (name, version).
    formulae: Vec<(String, String)>,
    casks: Vec<(String, String)>,
    tools: Vec<Package>,
    skipped: Vec<String>,
}

impl Mac {
    fn gather() -> Mac {
        let local = Local::installed();
        let (part, tools) = sweep::global_tools();
        let (formulae, casks) = inventory::homebrew();
        let mut skipped = local.part.skipped.clone();
        skipped.extend(part.skipped.into_iter().filter(|s| !s.contains("not installed") && !s.contains("nothing installed")));
        Mac { local, formulae, casks, tools, skipped }
    }

    /// What was read, as graph units: the apps, Homebrew, global tools and project packages.
    fn graph(&self) -> graph::Batch {
        let mut batch = self.local.graph();
        batch.extend(inventory::homebrew_graph(&self.formulae, &self.casks));
        batch.extend(inventory::tools_graph(&self.tools));
        batch
    }

    fn project_packages(&self) -> usize {
        self.local.projects.iter().map(|p| p.packages.len()).sum()
    }

    fn summary(&self) -> String {
        format!(
            "this Mac: macOS {}, Safari {}, {}, {} and {}, {}, {} in {}",
            if self.local.os.is_empty() { "?" } else { &self.local.os },
            if self.local.safari.is_empty() { "?" } else { &self.local.safari },
            plural(self.local.apps.len(), "app", "apps"),
            plural(self.formulae.len(), "Homebrew formula", "Homebrew formulae"),
            plural(self.casks.len(), "cask", "casks"),
            plural(self.tools.len(), "global tool", "global tools"),
            plural(self.project_packages(), "project package", "project packages"),
            plural(self.local.projects.len(), "project", "projects"),
        )
    }
}

// ---------------------------------------------------------------------------------------------
// Versions

#[derive(PartialEq, Debug)]
enum Token {
    Num(u64),
    /// A pre-release word (dev, alpha, beta, rc …): before the release.
    Pre(u8, String),
    /// Any other letters (openssl's 1.1.1w, post releases): after it.
    Post(String),
}

fn tokens(version: &str) -> Vec<Token> {
    let core = version.trim().trim_start_matches(['v', 'V']).split('+').next().unwrap_or("");
    // Homebrew's revision (`3.5.0_1`) is not part of the version.
    let core = match core.rsplit_once('_') {
        Some((head, rev)) if !rev.is_empty() && rev.chars().all(|c| c.is_ascii_digit()) => head,
        _ => core,
    };
    let mut out = Vec::new();
    let mut chars = core.chars().peekable();
    while let Some(&c) = chars.peek() {
        if c.is_ascii_digit() {
            let mut n = String::new();
            while let Some(&d) = chars.peek().filter(|d| d.is_ascii_digit()) {
                n.push(d);
                chars.next();
            }
            out.push(Token::Num(n.parse().unwrap_or(u64::MAX)));
        } else if c.is_ascii_alphabetic() {
            let mut w = String::new();
            while let Some(&d) = chars.peek().filter(|d| d.is_ascii_alphabetic()) {
                w.push(d.to_ascii_lowercase());
                chars.next();
            }
            let pre = match w.as_str() {
                "dev" | "snapshot" => Some(0),
                "a" | "alpha" => Some(1),
                "b" | "beta" => Some(2),
                "pre" | "preview" | "c" | "rc" => Some(3),
                _ => None,
            };
            out.push(match pre {
                Some(rank) => Token::Pre(rank, w),
                None => Token::Post(w),
            });
        } else {
            chars.next();
        }
    }
    out
}

/// Compare versions of any ecosystem as well as can be done without its rules: numbers as
/// numbers, pre-release words before the release, other letters after it. `None` when either
/// has no number.
pub fn loose_cmp(a: &str, b: &str) -> Option<Ordering> {
    let (a, b) = (tokens(a), tokens(b));
    if !a.iter().any(|t| matches!(t, Token::Num(_))) || !b.iter().any(|t| matches!(t, Token::Num(_))) {
        return None;
    }
    let n = a.len().max(b.len());
    for i in 0..n {
        let order = match (a.get(i), b.get(i)) {
            (Some(Token::Num(x)), Some(Token::Num(y))) => x.cmp(y),
            (Some(Token::Pre(x, s)), Some(Token::Pre(y, t))) => x.cmp(y).then(s.cmp(t)),
            (Some(Token::Post(s)), Some(Token::Post(t))) => s.cmp(t),
            (Some(Token::Num(_)), Some(_)) => Ordering::Greater,
            (Some(_), Some(Token::Num(_))) => Ordering::Less,
            (Some(Token::Pre(..)), Some(Token::Post(_))) => Ordering::Less,
            (Some(Token::Post(_)), Some(Token::Pre(..))) => Ordering::Greater,
            (Some(Token::Num(x)), None) => return Some(if *x == 0 && a[i..].iter().all(|t| *t == Token::Num(0)) { Ordering::Equal } else { Ordering::Greater }),
            (None, Some(Token::Num(y))) => return Some(if *y == 0 && b[i..].iter().all(|t| *t == Token::Num(0)) { Ordering::Equal } else { Ordering::Less }),
            (Some(Token::Pre(..)), None) => Ordering::Less,
            (None, Some(Token::Pre(..))) => Ordering::Greater,
            (Some(Token::Post(_)), None) => Ordering::Greater,
            (None, Some(Token::Post(_))) => Ordering::Less,
            (None, None) => Ordering::Equal,
        };
        if order != Ordering::Equal {
            return Some(order);
        }
    }
    Some(Ordering::Equal)
}

/// Semantic versioning: the core as numbers, then any pre-release before the release.
fn semver_cmp(a: &str, b: &str) -> Option<Ordering> {
    let split = |v: &str| {
        let v = v.trim().trim_start_matches('v').split('+').next().unwrap_or("").to_owned();
        match v.split_once('-') {
            Some((core, pre)) => (core.to_owned(), Some(pre.to_owned())),
            None => (v, None),
        }
    };
    let ((ca, pa), (cb, pb)) = (split(a), split(b));
    let core = version_cmp(&ca, &cb)?;
    if core != Ordering::Equal {
        return Some(core);
    }
    Some(match (pa, pb) {
        (None, None) => Ordering::Equal,
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(x), Some(y)) => {
            let (xs, ys): (Vec<&str>, Vec<&str>) = (x.split('.').collect(), y.split('.').collect());
            for (p, q) in xs.iter().zip(&ys) {
                let order = match (p.parse::<u64>(), q.parse::<u64>()) {
                    (Ok(m), Ok(n)) => m.cmp(&n),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    _ => p.cmp(q),
                };
                if order != Ordering::Equal {
                    return Some(order);
                }
            }
            xs.len().cmp(&ys.len())
        }
    })
}

fn at_least(v: &str, bound: &str) -> Option<bool> {
    loose_cmp(v, bound).map(|o| o != Ordering::Less)
}

// ---------------------------------------------------------------------------------------------
// Apple: the macOS and Safari releases whose notes name the CVE.

/// (major -> the first release of that major that fixes it) in one SOFA feed.
fn fixed_in(feed: &Value, list: &str, cves: &[String]) -> BTreeMap<u64, String> {
    let mut fixes: BTreeMap<u64, String> = BTreeMap::new();
    for line in feed[list].as_array().into_iter().flatten() {
        let releases = line["SecurityReleases"].as_array().into_iter().flatten().chain(std::iter::once(&line["Latest"]));
        for release in releases {
            let Some(version) = release["ProductVersion"].as_str() else { continue };
            let names = cves.iter().any(|c| release["CVEs"].get(c).is_some());
            if let (true, Some(m)) = (names, major(version))
                && fixes.get(&m).is_none_or(|v| version_cmp(version, v) == Some(Ordering::Less))
            {
                fixes.insert(m, version.to_owned());
            }
        }
    }
    fixes
}

/// True when Apple's notes name it (then the CPE check of macOS and Safari is not needed).
fn apple(feeds: &Feeds, cves: &[String], mac: Option<&Mac>, affects: &mut Vec<CveAffects>, matches: &mut Vec<CveMatch>) -> bool {
    if cves.is_empty() {
        return false;
    }
    let mut named = false;
    for (product, feed, list) in [("macOS", &feeds.sofa, "OSVersions"), ("Safari", &feeds.safari, "AppVersions")] {
        let Some(feed) = feed else { continue };
        let fixes = fixed_in(feed, list, cves);
        if fixes.is_empty() {
            continue;
        }
        named = true;
        for (m, version) in &fixes {
            affects.push(CveAffects { source: "apple".into(), what: format!("{product} {m}"), versions: format!("fixed in {version}") });
        }
        let Some(mac) = mac else { continue };
        let installed = if product == "macOS" { &mac.local.os } else { &mac.local.safari };
        if installed.is_empty() {
            continue;
        }
        let ours = major(installed).unwrap_or(0);
        let listed = fixes.keys().map(|m| format!("{product} {m}")).collect::<Vec<_>>().join(", ");
        let (verdict, why, fix) = match fixes.get(&ours) {
            Some(fix) if version_cmp(installed, fix) != Some(Ordering::Less) => {
                ("fixed", format!("{product} {installed} already has the fix (it came in {fix})"), None)
            }
            Some(fix) => ("affected", format!("{product} {installed} is below {fix}, which fixes it"), Some(format!("Install {product} {fix} or later: {UPDATE}"))),
            None if fixes.keys().all(|m| *m < ours) => (
                "not-affected",
                format!("Apple lists the fix for {listed} only; {product} {ours} came later and is not named, so it most likely never had the flaw"),
                None,
            ),
            None => (
                "unknown",
                format!("Apple lists the fix for {listed}, not for {product} {ours}; if {ours} has the flaw, upgrading is the fix"),
                Some(UPDATE.to_owned()),
            ),
        };
        let about = if product == "macOS" { ("OS".to_owned(), "macOS".to_owned()) } else { ("App".to_owned(), "com.apple.Safari".to_owned()) };
        let fixed_in = fixes.get(&ours).cloned().unwrap_or_default();
        matches.push(CveMatch { what: product.into(), version: installed.clone(), place: "this Mac".into(), verdict: verdict.into(), why, fix, about: Some(about), fixed_in });
    }
    named
}

// ---------------------------------------------------------------------------------------------
// OSV packages: lockfiles in projects and global tools.

/// PyPI names compare case-insensitively with `-`, `_` and `.` alike.
fn same_package(ecosystem: &str, a: &str, b: &str) -> bool {
    match ecosystem {
        "PyPI" => {
            let norm = |s: &str| s.to_ascii_lowercase().replace(['_', '.'], "-");
            norm(a) == norm(b)
        }
        // crates.io treats `-` and `_` alike.
        "crates.io" => a.replace('_', "-").eq_ignore_ascii_case(&b.replace('_', "-")),
        "npm" | "Go" => a == b,
        _ => a.eq_ignore_ascii_case(b),
    }
}

/// (verdict, why, the fixed version when there is one).
fn osv_verdict(package: &OsvPackage, version: &str) -> (&'static str, String, Option<String>) {
    if package.versions.iter().any(|v| v == version || (loose_cmp(v, version) == Some(Ordering::Equal) && !v.is_empty())) {
        let fixed = next_fixed(package, version);
        return ("affected", "the advisory lists this exact version".into(), fixed);
    }
    let usable: Vec<&(String, Events)> = package.ranges.iter().filter(|(kind, _)| kind == "SEMVER" || kind == "ECOSYSTEM").collect();
    if usable.is_empty() {
        return if package.versions.is_empty() {
            ("unknown", "the advisory gives only source commits, no versions".into(), None)
        } else {
            ("not-affected", "this version is not in the advisory's list".into(), None)
        };
    }
    let mut above_fix = false;
    for (kind, events) in usable {
        let cmp = |a: &str, b: &str| if kind == "SEMVER" { semver_cmp(a, b) } else { loose_cmp(a, b) };
        let mut events: Vec<&(String, String)> = events.iter().filter(|(e, _)| e != "limit").collect();
        let comparable = events.iter().all(|(_, v)| v == "0" || cmp(v, version).is_some());
        if !comparable || cmp(version, version).is_none() {
            return ("unknown", format!("{version} cannot be compared with the advisory's versions"), None);
        }
        events.sort_by(|a, b| if a.1 == "0" { Ordering::Less } else if b.1 == "0" { Ordering::Greater } else { cmp(&a.1, &b.1).unwrap_or(Ordering::Equal) });
        let mut inside = false;
        for (event, at) in &events {
            let order = if at == "0" { Ordering::Greater } else { cmp(version, at).unwrap_or(Ordering::Equal) };
            match event.as_str() {
                "introduced" if order != Ordering::Less => inside = true,
                "fixed" if order != Ordering::Less => {
                    inside = false;
                    above_fix = true;
                }
                "last_affected" if order == Ordering::Greater => inside = false,
                _ => {}
            }
        }
        if inside {
            let fixed = next_fixed(package, version);
            let why = match &fixed {
                Some(fixed) => format!("{version} is below {fixed}, which fixes it"),
                None => format!("{version} is in the affected range and no fixed release is listed"),
            };
            return ("affected", why, fixed);
        }
    }
    if above_fix { ("fixed", format!("{version} already has the fix"), None) } else { ("not-affected", format!("{version} is outside the affected range"), None) }
}

/// The lowest `fixed` version above `version`.
fn next_fixed(package: &OsvPackage, version: &str) -> Option<String> {
    package
        .ranges
        .iter()
        .flat_map(|(_, events)| events.iter())
        .filter(|(e, v)| e == "fixed" && loose_cmp(v, version) == Some(Ordering::Greater))
        .map(|(_, v)| v.clone())
        .min_by(|a, b| loose_cmp(a, b).unwrap_or(Ordering::Equal))
}

fn range_text(package: &OsvPackage) -> String {
    let mut parts: Vec<String> = Vec::new();
    for (kind, events) in &package.ranges {
        if kind == "GIT" {
            continue;
        }
        let mut text = Vec::new();
        for (event, at) in events {
            match event.as_str() {
                "introduced" if at != "0" => text.push(format!(">= {at}")),
                "fixed" => text.push(format!("< {at}")),
                "last_affected" => text.push(format!("<= {at}")),
                _ => {}
            }
        }
        parts.push(if text.is_empty() { "all versions".into() } else { text.join(", ") });
    }
    if parts.is_empty() && !package.versions.is_empty() {
        let shown: Vec<&str> = package.versions.iter().take(4).map(String::as_str).collect();
        parts.push(format!("{}{}", shown.join(", "), if package.versions.len() > 4 { format!(" and {} more", package.versions.len() - 4) } else { String::new() }));
    }
    shorten(&parts.join("; "), 120)
}

fn packages(list: &[OsvPackage], mac: &Mac, affects: &mut Vec<CveAffects>, matches: &mut Vec<CveMatch>) {
    for package in list {
        affects.push(CveAffects { source: "osv".into(), what: format!("{} {}", package.ecosystem, package.name), versions: range_text(package) });
        for project in &mac.local.projects {
            for (eco, name, version) in &project.packages {
                if *eco != package.ecosystem || !same_package(eco, name, &package.name) {
                    continue;
                }
                let (verdict, why, fixed) = osv_verdict(package, version);
                let root = tilde(&project.root);
                let fix = (verdict == "affected").then(|| project_fix(eco, name, fixed.as_deref(), &root));
                let about = Some(("Package".to_owned(), format!("{eco}:{name}")));
                matches.push(CveMatch { what: name.clone(), version: version.clone(), place: root, verdict: verdict.into(), why, fix, about, fixed_in: fixed.clone().unwrap_or_default() });
            }
        }
        for tool in mac.tools.iter().filter(|t| t.ecosystem == package.ecosystem && same_package(t.ecosystem, &t.name, &package.name)) {
            let (verdict, why, fixed) = osv_verdict(package, &tool.version);
            let fix = (verdict == "affected").then(|| tool.fix.clone());
            let about = Some(("Package".to_owned(), format!("{}:{}", tool.ecosystem, tool.name)));
            matches.push(CveMatch { what: tool.name.clone(), version: tool.version.clone(), place: format!("global {} tool", tool.manager), verdict: verdict.into(), why, fix, about, fixed_in: fixed.unwrap_or_default() });
        }
    }
}

fn project_fix(ecosystem: &str, name: &str, fixed: Option<&str>, root: &str) -> String {
    let at = fixed.map(|f| format!("@{f}")).unwrap_or_default();
    match ecosystem {
        "npm" => format!("cd {root} && npm install {name}{}", if at.is_empty() { "@latest".into() } else { at }),
        "crates.io" => format!("cd {root} && cargo update -p {name}"),
        "PyPI" => format!("cd {root} && pip install -U '{name}{}'", fixed.map(|f| format!(">={f}")).unwrap_or_default()),
        "Go" => format!("cd {root} && go get {name}@{}", fixed.map(|f| format!("v{f}")).unwrap_or_else(|| "latest".into())),
        "RubyGems" => format!("cd {root} && bundle update {name}"),
        _ => format!("Update {name} in {root}{}", fixed.map(|f| format!(" to {f} or later")).unwrap_or_default()),
    }
}

// ---------------------------------------------------------------------------------------------
// NVD CPEs: apps, Homebrew, macOS and Safari, Electron.

fn norm(text: &str) -> String {
    let mut out = String::new();
    for c in text.to_ascii_lowercase().chars() {
        let c = if c.is_ascii_alphanumeric() { c } else { '_' };
        if !(c == '_' && out.ends_with('_')) {
            out.push(c);
        }
    }
    out.trim_matches('_').to_owned()
}

/// Common products whose names differ between NVD and the Mac: (vendor, products, bundle ids,
/// Homebrew formulae or casks).
const ALIASES: &[(&str, &[&str], &[&str], &[&str])] = &[
    ("google", &["chrome"], &["com.google.Chrome"], &["google-chrome"]),
    ("mozilla", &["firefox", "firefox_esr"], &["org.mozilla.firefox"], &["firefox"]),
    ("mozilla", &["thunderbird"], &["org.mozilla.thunderbird"], &["thunderbird"]),
    ("microsoft", &["edge", "edge_chromium"], &["com.microsoft.edgemac"], &["microsoft-edge"]),
    ("microsoft", &["teams"], &["com.microsoft.teams2", "com.microsoft.teams"], &["microsoft-teams"]),
    ("microsoft", &["visual_studio_code"], &["com.microsoft.VSCode"], &["visual-studio-code"]),
    (
        "microsoft",
        &["office", "365_apps", "word", "excel", "powerpoint", "outlook", "office_long_term_servicing_channel"],
        &["com.microsoft.Word", "com.microsoft.Excel", "com.microsoft.Powerpoint", "com.microsoft.Outlook"],
        &["microsoft-office"],
    ),
    ("zoom", &["zoom", "meetings", "workplace", "workplace_desktop", "zoom_workplace"], &["us.zoom.xos"], &["zoom"]),
    ("slack", &["slack"], &["com.tinyspeck.slackmacgap"], &["slack"]),
    ("docker", &["desktop", "docker_desktop"], &["com.docker.docker"], &["docker", "docker-desktop"]),
    ("openssl", &["openssl"], &[], &["openssl@3", "openssl@1.1", "openssl"]),
    ("haxx", &["curl", "libcurl"], &[], &["curl"]),
    ("git-scm", &["git"], &[], &["git"]),
    ("nodejs", &["node.js", "nodejs"], &[], &["node"]),
    ("openbsd", &["openssh"], &[], &["openssh"]),
    ("sqlite", &["sqlite"], &[], &["sqlite"]),
    ("webmproject", &["libwebp"], &[], &["webp"]),
    ("libexpat_project", &["libexpat"], &[], &["expat"]),
    ("tukaani", &["xz"], &[], &["xz"]),
    ("videolan", &["vlc_media_player", "vlc"], &["org.videolan.vlc"], &["vlc"]),
    ("signal", &["signal-desktop", "signal_desktop"], &["org.whispersystems.signal-desktop"], &["signal"]),
    ("telegram", &["telegram_desktop", "telegram"], &["ru.keepcoder.Telegram", "org.telegram.desktop"], &["telegram", "telegram-desktop"]),
    ("1password", &["1password"], &["com.1password.1password"], &["1password"]),
    ("iterm2", &["iterm2"], &["com.googlecode.iterm2"], &["iterm2"]),
    ("oracle", &["vm_virtualbox", "virtualbox"], &["org.virtualbox.app.VirtualBox"], &["virtualbox"]),
    ("python", &["python"], &[], &["python"]),
    ("golang", &["go"], &[], &["go"]),
];

/// One thing on this Mac a CPE may name.
struct Candidate {
    what: String,
    version: String,
    place: String,
    fix: Option<String>,
    /// Its graph node (label, key).
    about: Option<(String, String)>,
}

fn candidates(vendor: &str, product: &str, mac: &Mac) -> Vec<Candidate> {
    let (v, p) = (norm(vendor), norm(product));
    let both = format!("{v}_{p}");
    let alias = ALIASES.iter().find(|(av, products, _, _)| norm(av) == v && products.iter().any(|ap| norm(ap) == p));
    let mut found = Vec::new();
    for app in &mac.local.apps {
        let id = app.id.to_ascii_lowercase();
        let parts: Vec<&str> = id.split('.').collect();
        let (org, last) = (parts.get(1).copied().unwrap_or(""), parts.last().copied().unwrap_or(""));
        let name = norm(&app.name);
        let hit = alias.is_some_and(|(_, _, ids, _)| ids.iter().any(|i| i.eq_ignore_ascii_case(&app.id)))
            || (alias.is_none() && (name == p && (p.len() > 3 || org == v) || name == both || (norm(last) == p && norm(org) == v)));
        if hit {
            found.push(Candidate {
                what: app.name.clone(),
                version: app.version.clone(),
                place: tilde(&app.path),
                fix: Some(format!("Update {} (its Check for Updates menu, or the App Store)", app.name)),
                about: (!app.id.is_empty()).then(|| ("App".to_owned(), app.id.clone())),
            });
        }
    }
    for (list, cask) in [(&mac.formulae, false), (&mac.casks, true)] {
        for (name, version) in list.iter() {
            let base = norm(name.split('@').next().unwrap_or(name));
            let hit = match alias {
                Some((_, _, _, brew)) => brew.iter().any(|b| b == name || norm(b) == base && !b.contains('@')),
                None => base == p || (cask && base == both),
            };
            if hit {
                found.push(Candidate {
                    what: name.clone(),
                    version: version.clone(),
                    place: if cask { "Homebrew cask".into() } else { "Homebrew".into() },
                    fix: Some(if cask { format!("brew upgrade --cask {name}") } else { format!("brew upgrade {name}") }),
                    about: Some(("Formula".to_owned(), name.clone())),
                });
            }
        }
    }
    found
}

/// An affected Homebrew formula: what installed uses it, and, when Homebrew does not ship the fix
/// yet, the command that still closes it: removing it when nothing uses it, else building the
/// project's newest source (`--HEAD`), which has the fix. Otherwise no command is offered.
fn homebrew_reach(matches: &mut [CveMatch]) {
    for m in matches.iter_mut().filter(|m| m.verdict == "affected" && m.place == "Homebrew") {
        let users = brew_users(&m.what);
        if let Some(users) = &users {
            m.why = match users.len() {
                0 => format!("{}; nothing installed uses it", m.why),
                n => format!("{}; used by {}{}", m.why, users.iter().take(6).cloned().collect::<Vec<_>>().join(", "), if n > 6 { format!(" and {} more", n - 6) } else { String::new() }),
            };
        }
        if m.fixed_in.is_empty() {
            continue;
        }
        let Some((newest, head)) = brew_newest(&m.what) else { continue };
        if version_cmp(&newest, &m.fixed_in) != Some(Ordering::Less) {
            continue;
        }
        let name = m.what.clone();
        m.why = format!("{}; Homebrew's newest {name} is {newest}, so an upgrade cannot fix it yet", m.why);
        m.fix = if users.as_ref().is_some_and(Vec::is_empty) {
            m.why.push_str("; removing it closes the flaw (undo: brew install ");
            m.why.push_str(&name);
            m.why.push(')');
            Some(format!("brew uninstall {name}"))
        } else if head {
            m.why.push_str(&format!("; building {name} from its project's newest source (HEAD) has the fix, outside Homebrew's tested releases (undo: brew uninstall --ignore-dependencies {name} && brew install {name})"));
            Some(format!("brew uninstall --ignore-dependencies {name} && brew install --HEAD {name}"))
        } else {
            None
        };
    }
}

/// The installed formulae that use a formula (`brew uses --installed`).
fn brew_users(name: &str) -> Option<Vec<String>> {
    let out = crate::util::run("brew", &["uses", "--installed", name], Duration::from_secs(30)).ok().filter(|out| out.ok)?;
    Some(out.stdout.split_whitespace().map(str::to_owned).collect())
}

/// Homebrew's newest version of a formula (its local catalogue, as of the last `brew update`) and
/// whether it can be built from the project's newest source, remembered for an hour.
fn brew_newest(name: &str) -> Option<(String, bool)> {
    static NEWEST: Mutex<BTreeMap<String, (u64, String, bool)>> = Mutex::new(BTreeMap::new());
    if let Some((at, version, head)) = NEWEST.lock().ok()?.get(name)
        && at + 3_600_000 > now_ms()
    {
        return Some((version.clone(), *head));
    }
    let out = crate::util::run("brew", &["info", "--json=v2", name], Duration::from_secs(30)).ok().filter(|out| out.ok)?;
    let info: Value = serde_json::from_str(&out.stdout).ok()?;
    let version = info.pointer("/formulae/0/versions/stable")?.as_str()?.to_owned();
    let head = info.pointer("/formulae/0/versions/head").is_some_and(|h| !h.is_null());
    NEWEST.lock().ok()?.insert(name.to_owned(), (now_ms(), version.clone(), head));
    Some((version, head))
}

/// Whether one CPE covers a version: Some(true) inside, Some(false) outside, None unknown.
fn cpe_covers(cpe: &Cpe, version: &str) -> Option<bool> {
    if !cpe.version.is_empty() {
        return loose_cmp(version, &cpe.version).map(|o| o == Ordering::Equal);
    }
    let bounded = [&cpe.start_incl, &cpe.start_excl, &cpe.end_incl, &cpe.end_excl].iter().any(|b| !b.is_empty());
    if !bounded {
        return None;
    }
    let mut inside = true;
    if !cpe.start_incl.is_empty() {
        inside &= at_least(version, &cpe.start_incl)?;
    }
    if !cpe.start_excl.is_empty() {
        inside &= loose_cmp(version, &cpe.start_excl)? == Ordering::Greater;
    }
    if !cpe.end_incl.is_empty() {
        inside &= loose_cmp(version, &cpe.end_incl)? != Ordering::Greater;
    }
    if !cpe.end_excl.is_empty() {
        inside &= loose_cmp(version, &cpe.end_excl)? == Ordering::Less;
    }
    Some(inside)
}

fn cpe_range(cpe: &Cpe) -> String {
    if !cpe.version.is_empty() {
        return format!("= {}", cpe.version);
    }
    let mut text = Vec::new();
    for (op, bound) in [(">=", &cpe.start_incl), (">", &cpe.start_excl), ("<=", &cpe.end_incl), ("<", &cpe.end_excl)] {
        if !bound.is_empty() {
            text.push(format!("{op} {bound}"));
        }
    }
    if text.is_empty() { "all versions".into() } else { text.join(", ") }
}

/// The verdict of a group of CPEs (one product) for an installed version.
fn cpe_verdict(group: &[&Cpe], version: &str) -> (&'static str, String, Option<String>) {
    if version.is_empty() {
        return ("unknown", "its version is not known".into(), None);
    }
    let mut unknown = false;
    for cpe in group {
        match cpe_covers(cpe, version) {
            Some(true) => {
                let fixed = (!cpe.end_excl.is_empty()).then(|| cpe.end_excl.clone());
                let why = match &fixed {
                    Some(fixed) => format!("{version} is below {fixed}, which fixes it"),
                    None if !cpe.end_incl.is_empty() => format!("{version} is at or below {}, the last affected version", cpe.end_incl),
                    None => format!("{version} is in the affected range ({})", cpe_range(cpe)),
                };
                return ("affected", why, fixed);
            }
            Some(false) => {}
            None => unknown = true,
        }
    }
    if unknown {
        return ("unknown", "the advisory names no version range for it".into(), None);
    }
    let above = group.iter().any(|c| {
        let end = if c.end_excl.is_empty() { &c.end_incl } else { &c.end_excl };
        !end.is_empty() && at_least(version, end) == Some(true)
    });
    if above { ("fixed", format!("{version} is past the affected versions"), None) } else { ("not-affected", format!("{version} is outside the affected versions"), None) }
}

fn cpes(list: &[Cpe], mac: &Mac, feeds: &Feeds, apple_named: bool, affects: &mut Vec<CveAffects>, matches: &mut Vec<CveMatch>) {
    let mut groups: BTreeMap<(String, String, String), Vec<&Cpe>> = BTreeMap::new();
    for cpe in list {
        groups.entry((cpe.part.clone(), cpe.vendor.clone(), cpe.product.clone())).or_default().push(cpe);
    }
    for ((part, vendor, product), group) in &groups {
        let ranges: Vec<String> = group.iter().take(4).map(|c| cpe_range(c)).collect();
        let more = if group.len() > 4 { format!(" and {} more ranges", group.len() - 4) } else { String::new() };
        let kind = match part.as_str() {
            "o" => " (operating system)",
            "h" => " (hardware)",
            _ => "",
        };
        affects.push(CveAffects { source: "nvd".into(), what: format!("{} {}{kind}", vendor.replace('_', " "), product.replace('_', " ")), versions: format!("{}{more}", ranges.join("; ")) });

        let installed: Vec<Candidate> = match (vendor.as_str(), product.as_str()) {
            ("apple", "macos" | "mac_os_x" | "mac_os") if !apple_named && !mac.local.os.is_empty() => {
                vec![Candidate { what: "macOS".into(), version: mac.local.os.clone(), place: "this Mac".into(), fix: Some(UPDATE.into()), about: Some(("OS".into(), "macOS".into())) }]
            }
            ("apple", "safari") if !apple_named && !mac.local.safari.is_empty() => {
                vec![Candidate { what: "Safari".into(), version: mac.local.safari.clone(), place: "this Mac".into(), fix: Some(UPDATE.into()), about: Some(("App".into(), "com.apple.Safari".into())) }]
            }
            ("apple", _) => Vec::new(),
            ("electronjs", "electron") => mac
                .local
                .apps
                .iter()
                .filter_map(|a| {
                    Some(Candidate {
                        what: format!("{} (Electron)", a.name),
                        version: a.electron.clone()?,
                        place: tilde(&a.path),
                        fix: Some(format!("Update {}; it ships its own Electron", a.name)),
                        about: (!a.id.is_empty()).then(|| ("App".to_owned(), a.id.clone())),
                    })
                })
                .collect(),
            _ if part == "a" => candidates(vendor, product, mac),
            _ => Vec::new(),
        };
        for candidate in installed {
            let (verdict, why, fixed) = cpe_verdict(group, &candidate.version);
            let fix = (verdict == "affected").then(|| match (&candidate.fix, &fixed) {
                (Some(fix), Some(fixed)) if fix.starts_with("Update ") => format!("{fix} to {fixed} or later"),
                (Some(fix), _) => fix.clone(),
                (None, _) => String::new(),
            });
            matches.push(CveMatch {
                what: candidate.what,
                version: candidate.version,
                place: candidate.place,
                verdict: verdict.into(),
                why,
                fix: fix.filter(|f| !f.is_empty()),
                about: candidate.about,
                fixed_in: fixed.unwrap_or_default(),
            });
        }
        // Chrome's flaws are Chromium's: Electron apps carry their own copy.
        if vendor == "google" && product == "chrome" {
            chromium(group, mac, feeds, matches);
        }
    }
}

fn chromium(group: &[&Cpe], mac: &Mac, feeds: &Feeds, matches: &mut Vec<CveMatch>) {
    let Some(index) = &feeds.electron else { return };
    let Some(fixed) = group.iter().map(|c| c.end_excl.as_str()).filter(|e| !e.is_empty()).max_by(|a, b| loose_cmp(a, b).unwrap_or(Ordering::Equal)) else {
        return;
    };
    let Some(fixed_major) = major(fixed) else { return };
    for app in &mac.local.apps {
        let Some(electron) = &app.electron else { continue };
        let Some(chromium) = major(electron).and_then(|m| index.chrome.get(&m)).and_then(|c| major(c)) else { continue };
        let (verdict, why) = if chromium < fixed_major {
            ("affected", format!("Electron {electron} carries Chromium {chromium}, older than Chrome {fixed}, which fixes it (likely affected, if the app uses the flawed part)"))
        } else if chromium > fixed_major {
            ("not-affected", format!("Electron {electron} carries Chromium {chromium}, newer than the fix in Chrome {fixed}"))
        } else {
            ("unknown", format!("Electron {electron} carries Chromium {chromium}, the same major as the fix in Chrome {fixed}"))
        };
        matches.push(CveMatch {
            what: format!("{} (Chromium inside Electron)", app.name),
            version: electron.clone(),
            place: tilde(&app.path),
            verdict: verdict.into(),
            why,
            fix: (verdict == "affected").then(|| format!("Update {}; it ships its own Chromium", app.name)),
            about: (!app.id.is_empty()).then(|| ("App".to_owned(), app.id.clone())),
            fixed_in: String::new(),
        });
    }
}

// ---------------------------------------------------------------------------------------------
// The verdict, in one sentence.

fn verdict(report: &mut CveReport, advisory: &Advisory, looked: bool) {
    let id = report.id.clone();
    let count = |v: &str| report.matches.iter().filter(|m| m.verdict == v).count();
    let (affected, fixed, clear, unknown) = (count("affected"), count("fixed"), count("not-affected"), count("unknown"));
    let first = |v: &str| report.matches.iter().find(|m| m.verdict == v).cloned();
    let named = |m: &CveMatch| {
        let place = if m.place.is_empty() || m.place == "this Mac" { String::new() } else { format!(" ({})", m.place) };
        if m.why.starts_with(&m.what) { format!("{}{place}", m.why) } else { format!("{}{place}: {}", m.what, m.why) }
    };
    let more = |n: usize| if n > 1 { format!(", and {}", plural(n - 1, "more match", "more matches")) } else { String::new() };

    let mut risk = Vec::new();
    if let Some(kev) = &report.kev {
        risk.push(format!("it is actively exploited (CISA KEV{})", if kev.ransomware { ", used in ransomware" } else { "" }));
    }
    if let Some(cvss) = report.cvss.as_ref().filter(|c| c.score > 0.0) {
        risk.push(format!("rated {} (CVSS {:.1})", cvss.severity.to_lowercase(), cvss.score));
    } else if let Some(cvss) = report.cvss.as_ref().filter(|c| !c.severity.is_empty()) {
        risk.push(format!("rated {}", cvss.severity.to_lowercase()));
    }
    if risk.len() < 2
        && let Some(epss) = &report.epss
    {
        risk.push(format!("exploit likelihood {:.1}% in the next 30 days (EPSS)", epss.score * 100.0));
    }
    let risk = if risk.is_empty() { String::new() } else { format!("; {}", risk.join(", ")) };
    let covers = !advisory.cpes.is_empty() || !advisory.packages.is_empty() || report.affects.iter().any(|a| a.source == "apple");

    let (verdict, text) = if !advisory.found && report.affects.is_empty() {
        let why = if advisory.skipped.is_empty() { String::new() } else { format!(" ({})", advisory.skipped.join("; ")) };
        ("not-found", format!("No advisory {id} was found in NVD or OSV{why}."))
    } else if let Some(m) = first("affected") {
        ("affected", format!("Your Mac is affected by {id}: {}{}{risk}.", named(&m), more(affected)))
    } else if let Some(m) = first("unknown").filter(|_| fixed == 0 && clear == 0) {
        ("unknown", format!("Could not tell whether your Mac is affected by {id}: {}{}{risk}.", named(&m), more(unknown)))
    } else if let Some(m) = first("fixed") {
        let open = if unknown > 0 { format!(" ({} could not be compared)", plural(unknown, "match", "matches")) } else { String::new() };
        ("fixed", format!("Your Mac has the fix for {id}: {}{}{open}{risk}.", named(&m), more(fixed)))
    } else if let Some(m) = first("not-affected") {
        let open = if unknown > 0 { format!(" ({} could not be compared)", plural(unknown, "match", "matches")) } else { String::new() };
        ("not-affected", format!("Your Mac is not affected by {id}: {}{}{open}{risk}.", named(&m), more(clear)))
    } else if !looked {
        ("unknown", format!("Could not tell whether your Mac is affected by {id}: this Mac's apps and packages could not be read in time{risk}."))
    } else if !covers {
        ("unknown", format!("Could not tell whether your Mac is affected by {id}: the advisory does not yet say which products and versions it covers{risk}."))
    } else {
        let what: Vec<String> = report.affects.iter().take(3).map(|a| a.what.clone()).collect();
        (
            "not-affected",
            format!(
                "Your Mac is not affected by {id} as far as can be seen: nothing installed matches what it covers ({}); a copy bundled inside another app cannot be seen{risk}.",
                what.join(", ")
            ),
        )
    };
    report.verdict = verdict.into();
    report.verdict_text = text;
    if report.title.is_empty() && !report.summary.is_empty() {
        let first_sentence = report.summary.split(". ").next().unwrap_or(&report.summary);
        report.title = shorten(first_sentence.trim_end_matches('.'), 160);
    }
}


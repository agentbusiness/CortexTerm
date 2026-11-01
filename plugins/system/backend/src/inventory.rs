//! Everything installed, not only Homebrew: apps and where they came from, which are out of date,
//! the macOS and Safari patch level, browsers, Electron apps, end-of-life runtimes, project
//! dependencies, Docker images, browser and editor extensions, and credentials left in files.
//! Feeds are kept in the graph (`docs`), refreshed at most daily, and used from the kept copy when
//! offline. What is installed is written to the graph with the sweep ([`Local::graph`]). Secret
//! checks report counts and places, never the text.

use crate::codesign;
use crate::sweep::{Part, secret_patterns, severity_of};
use crate::graph::{self, Batch, Props, r};
use cc_protocol::contracts::memory::GraphRef;
use crate::util::{home, now_ms, plural, run, tilde, which};
use crate::docs;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

const STEP: Duration = Duration::from_secs(15);
const DAY: Duration = Duration::from_secs(86_400);

pub const SOFA_MACOS: &str = "https://sofa.macadmins.io/v2/macos_data_feed.json";
pub const SOFA_SAFARI: &str = "https://sofa.macadmins.io/v2/safari_data_feed.json";
pub const KEV: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
pub const ELECTRON: &str = "https://releases.electronjs.org/releases.json";
const CHROME: &str = "https://versionhistory.googleapis.com/v1/chrome/platforms/mac/channels/stable/versions?pageSize=1";
const FIREFOX: &str = "https://product-details.mozilla.org/1.0/firefox_versions.json";
const CASKS: &str = "https://formulae.brew.sh/api/cask.json";
const MALEXT: &str = "https://raw.githubusercontent.com/toborrm9/malicious_extension_sentry/main/Malicious-Extensions.csv";

// ---------------------------------------------------------------------------------------------
// Dates and versions (also used by the posture checks)

/// Days since 1970-01-01, today.
pub fn today() -> i64 {
    (now_ms() / 86_400_000) as i64
}

/// Days since 1970-01-01 of a text that starts with "YYYY-MM-DD".
pub fn days(text: &str) -> Option<i64> {
    let text = text.trim();
    if text.get(4..5) != Some("-") || text.get(7..8) != Some("-") {
        return None;
    }
    let (y, m, d): (i64, i64, i64) = (text.get(0..4)?.parse().ok()?, text.get(5..7)?.parse().ok()?, text.get(8..10)?.parse().ok()?);
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's days_from_civil.
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * ((m + 9) % 12) + 2) / 5 + d - 1;
    Some(era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468)
}

pub fn numbers(version: &str) -> Option<Vec<u64>> {
    let core = version.trim().trim_start_matches(['v', 'V']).split([' ', '-', '+', ',', '(', '_']).next()?;
    if core.is_empty() {
        return None;
    }
    core.split('.').map(|p| p.parse().ok()).collect()
}

/// Compare dotted numeric versions ("26.7.2" > "26.7"); `None` when either is not one.
pub fn version_cmp(a: &str, b: &str) -> Option<Ordering> {
    let (mut a, mut b) = (numbers(a)?, numbers(b)?);
    let n = a.len().max(b.len());
    a.resize(n, 0);
    b.resize(n, 0);
    Some(a.cmp(&b))
}

fn newer(latest: &str, installed: &str) -> bool {
    version_cmp(latest, installed) == Some(Ordering::Greater)
}

pub fn major(version: &str) -> Option<u64> {
    numbers(version)?.first().copied()
}

fn names(list: &[String], max: usize) -> String {
    let mut text = list.iter().take(max).cloned().collect::<Vec<_>>().join(", ");
    if list.len() > max {
        text.push_str(&format!(" and {} more", list.len() - max));
    }
    text
}

// ---------------------------------------------------------------------------------------------
// Feeds

/// A feed as last kept, however old (for checks that run without the network). Blocking.
pub fn cached_feed(name: &str) -> Option<Vec<u8>> {
    docs::get_blocking(name).map(|doc| doc.bytes.to_vec())
}

/// [`cached_feed`] from async code.
pub async fn cached_feed_async(name: &str) -> Option<Vec<u8>> {
    docs::get(name).await.map(|doc| doc.bytes.to_vec())
}

fn host(url: &str) -> &str {
    url.split("://").nth(1).and_then(|r| r.split('/').next()).unwrap_or(url)
}

async fn get(client: &reqwest::Client, url: &str) -> Result<Vec<u8>, String> {
    let response = client.get(url).send().await.map_err(|e| format!("{}: {e}", host(url)))?;
    if !response.status().is_success() {
        return Err(format!("{} answered {}", host(url), response.status()));
    }
    response.bytes().await.map(|b| b.to_vec()).map_err(|e| format!("{}: {e}", host(url)))
}

/// Fresh: the kept copy when fetched within a day, else fetched and kept through `keep` (which
/// also checks it and may shrink it). Offline: the older kept copy and its age in days.
pub async fn feed(client: &reqwest::Client, name: &str, url: &str, keep: fn(&[u8]) -> Option<Vec<u8>>) -> Result<(Vec<u8>, Option<u64>), String> {
    feed_within(client, name, url, keep, DAY).await
}

/// [`feed`], downloaded again once the kept copy is older than `fresh`.
pub async fn feed_within(
    client: &reqwest::Client,
    name: &str,
    url: &str,
    keep: fn(&[u8]) -> Option<Vec<u8>>,
    fresh: Duration,
) -> Result<(Vec<u8>, Option<u64>), String> {
    let age = docs::fetched(name).map(|at| Duration::from_millis(now_ms().saturating_sub(at)));
    if age.is_some_and(|a| a < fresh)
        && let Some(doc) = docs::get(name).await
    {
        return Ok((doc.bytes.to_vec(), None));
    }
    let fetched = match get(client, url).await {
        Ok(bytes) => keep(&bytes).ok_or_else(|| format!("{} sent something unreadable", host(url))),
        Err(error) => Err(error),
    };
    match fetched {
        Ok(bytes) => {
            docs::put(name, url, bytes.clone(), now_ms());
            Ok((bytes, None))
        }
        Err(error) => match docs::get(name).await {
            Some(doc) => Ok((doc.bytes.to_vec(), Some(age.map(|a| a.as_secs() / 86_400).unwrap_or(0)))),
            None => Err(error),
        },
    }
}

/// The software feeds' document names and addresses (what `migrate` moves in), the
/// end-of-life lists aside (`eol-<product>.json`, from endoflife.date).
pub const FEEDS: &[(&str, &str)] = &[
    ("sofa-macos.json", SOFA_MACOS),
    ("sofa-safari.json", SOFA_SAFARI),
    (KEV_FILE, KEV),
    ("electron.json", ELECTRON),
    ("chrome-stable.json", CHROME),
    ("firefox.json", FIREFOX),
    ("homebrew-casks.json", CASKS),
    ("malicious-extensions.csv", MALEXT),
];

fn take(part: &mut Part, label: &str, result: Result<(Vec<u8>, Option<u64>), String>) -> Option<Vec<u8>> {
    match result {
        Ok((bytes, None)) => Some(bytes),
        Ok((bytes, Some(age))) => {
            part.checked.push(format!("{label} (offline: using the copy from {} ago)", plural(age as usize, "day", "days")));
            Some(bytes)
        }
        Err(error) => {
            part.skipped.push(format!("{label}: {error}, and no copy is cached"));
            None
        }
    }
}

pub fn json_ok(bytes: &[u8]) -> Option<Vec<u8>> {
    serde_json::from_slice::<serde::de::IgnoredAny>(bytes).ok().map(|_| bytes.to_vec())
}

/// The CISA KEV feed's cache file (`-v3`: rows with the vendor and product; the first version kept
/// only the ids).
pub const KEV_FILE: &str = "cisa-kev-v3.json";

/// One CISA KEV entry, as cached.
#[derive(Serialize, Deserialize, Default, Clone)]
pub struct KevRow {
    pub id: String,
    #[serde(default)]
    pub added: String,
    #[serde(default)]
    pub due: String,
    #[serde(default)]
    pub ransomware: bool,
    #[serde(default)]
    pub action: String,
    #[serde(default)]
    pub vendor: String,
    #[serde(default)]
    pub product: String,
}

/// CISA KEV, kept as its rows' id, dates, ransomware use, required action, vendor and product.
pub fn keep_kev(bytes: &[u8]) -> Option<Vec<u8>> {
    let kev: Value = serde_json::from_slice(bytes).ok()?;
    let text = |v: &Value, key: &str| v[key].as_str().unwrap_or("").to_owned();
    let rows: Vec<KevRow> = kev["vulnerabilities"]
        .as_array()?
        .iter()
        .filter_map(|v| {
            Some(KevRow {
                id: v["cveID"].as_str()?.to_owned(),
                added: text(v, "dateAdded"),
                due: text(v, "dueDate"),
                ransomware: v["knownRansomwareCampaignUse"].as_str() == Some("Known"),
                action: text(v, "requiredAction"),
                vendor: text(v, "vendorProject"),
                product: text(v, "product"),
            })
        })
        .collect();
    (!rows.is_empty()).then(|| serde_json::to_vec(&rows).ok()).flatten()
}

/// Electron: the newest stable major and, per major, its newest release's Chromium.
#[derive(Serialize, Deserialize, Default)]
pub struct ElectronIndex {
    pub stable: u64,
    pub chrome: BTreeMap<u64, String>,
}

pub fn keep_electron(bytes: &[u8]) -> Option<Vec<u8>> {
    let list: Vec<Value> = serde_json::from_slice(bytes).ok()?;
    let mut index = ElectronIndex::default();
    let mut newest: BTreeMap<u64, String> = BTreeMap::new();
    for release in &list {
        let (Some(version), Some(chrome)) = (release["version"].as_str(), release["chrome"].as_str()) else { continue };
        let Some(m) = major(version).filter(|_| !version.contains('-')) else { continue };
        if newest.get(&m).is_none_or(|n| newer(version, n)) {
            newest.insert(m, version.to_owned());
            index.chrome.insert(m, chrome.to_owned());
        }
        index.stable = index.stable.max(m);
    }
    (index.stable > 0).then(|| serde_json::to_vec(&index).ok()).flatten()
}

/// The Homebrew cask catalogue (about 19 MB), kept as token, version, app names and bundle ids.
#[derive(Serialize, Deserialize)]
struct Cask {
    token: String,
    version: String,
    apps: Vec<String>,
    ids: Vec<String>,
}

fn keep_casks(bytes: &[u8]) -> Option<Vec<u8>> {
    #[derive(Deserialize)]
    struct Raw {
        token: String,
        version: String,
        #[serde(default)]
        artifacts: Vec<Value>,
    }
    let raw: Vec<Raw> = serde_json::from_slice(bytes).ok()?;
    let file = |p: &str| Path::new(p).file_name().map(|f| f.to_string_lossy().to_lowercase());
    let casks: Vec<Cask> = raw
        .into_iter()
        .map(|cask| {
            let mut apps = Vec::new();
            let mut ids = Vec::new();
            for artifact in &cask.artifacts {
                if let Some(target) = artifact["target"].as_str().filter(|t| t.ends_with(".app")) {
                    apps.extend(file(target));
                }
                for item in artifact["app"].as_array().into_iter().flatten() {
                    match item {
                        Value::String(name) => apps.extend(file(name)),
                        other => apps.extend(other["target"].as_str().and_then(file)),
                    }
                }
                for step in artifact["uninstall"].as_array().into_iter().flatten() {
                    match &step["quit"] {
                        Value::String(id) => ids.push(id.clone()),
                        Value::Array(list) => ids.extend(list.iter().filter_map(|v| v.as_str().map(str::to_owned))),
                        _ => {}
                    }
                }
            }
            Cask { token: cask.token, version: cask.version, apps, ids }
        })
        .filter(|c| !c.apps.is_empty())
        .collect();
    (!casks.is_empty()).then(|| serde_json::to_vec(&casks).ok()).flatten()
}

fn keep_text(bytes: &[u8]) -> Option<Vec<u8>> {
    (bytes.len() > 1000).then(|| bytes.to_vec())
}

#[derive(Default)]
struct Feeds {
    sofa: Option<Value>,
    safari: Option<Value>,
    kev: HashSet<String>,
    electron: Option<ElectronIndex>,
    chrome: Option<String>,
    firefox: Option<Value>,
    casks: Vec<Cask>,
    malext: HashSet<String>,
}

async fn load_feeds(client: &reqwest::Client) -> (Feeds, Part) {
    let mut part = Part::default();
    let (sofa, safari, kev, electron, chrome, firefox, casks, malext) = tokio::join!(
        feed(client, "sofa-macos.json", SOFA_MACOS, json_ok),
        feed(client, "sofa-safari.json", SOFA_SAFARI, json_ok),
        feed(client, KEV_FILE, KEV, keep_kev),
        feed(client, "electron.json", ELECTRON, keep_electron),
        feed(client, "chrome-stable.json", CHROME, json_ok),
        feed(client, "firefox.json", FIREFOX, json_ok),
        feed(client, "homebrew-casks.json", CASKS, keep_casks),
        feed(client, "malicious-extensions.csv", MALEXT, keep_text),
    );
    let parse = |bytes: Option<Vec<u8>>| bytes.and_then(|b| serde_json::from_slice::<Value>(&b).ok());
    let mut feeds = Feeds {
        sofa: parse(take(&mut part, "SOFA macOS feed", sofa)),
        safari: parse(take(&mut part, "SOFA Safari feed", safari)),
        firefox: parse(take(&mut part, "Firefox versions", firefox)),
        ..Default::default()
    };
    if let Some(bytes) = take(&mut part, "CISA known exploited list", kev) {
        feeds.kev = serde_json::from_slice::<Vec<KevRow>>(&bytes).unwrap_or_default().into_iter().map(|r| r.id).collect();
    }
    feeds.electron = take(&mut part, "Electron releases", electron).and_then(|b| serde_json::from_slice(&b).ok());
    feeds.chrome = parse(take(&mut part, "Chrome versions", chrome))
        .and_then(|v| v["versions"][0]["version"].as_str().map(str::to_owned));
    feeds.casks = take(&mut part, "Homebrew cask catalogue", casks).and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
    if let Some(bytes) = take(&mut part, "malicious extension list", malext)
        && let Ok(id) = Regex::new(r"\b[a-p]{32}\b")
    {
        feeds.malext = id.find_iter(&String::from_utf8_lossy(&bytes)).map(|m| m.as_str().to_owned()).collect();
    }
    (feeds, part)
}

// ---------------------------------------------------------------------------------------------
// What is on this Mac (blocking)

pub struct App {
    pub name: String,
    pub id: String,
    pub version: String,
    pub path: PathBuf,
    /// App Store | Homebrew | Sparkle | Apple | direct
    pub origin: &'static str,
    feed: Option<String>,
    pub electron: Option<String>,
    /// Its main program and signature, when the apps were inspected.
    pub signature: Option<(PathBuf, codesign::Signature)>,
}

struct Toolchain {
    product: &'static str,
    label: &'static str,
    version: String,
    place: String,
}

#[derive(Default)]
pub struct Project {
    pub root: PathBuf,
    /// (OSV ecosystem, name, version)
    pub packages: BTreeSet<(&'static str, String, String)>,
    pub lockfiles: Vec<String>,
    envs: Vec<PathBuf>,
}

impl Project {
    /// A git repository, or a folder with lockfiles or a virtual environment.
    pub fn is_project(&self) -> bool {
        !self.lockfiles.is_empty() || self.root.join(".git").exists()
    }
}

/// What a look found no longer is marked gone (`memory.graph.retire`; its history and edges
/// stay, and a later look that finds it again brings it back). Only kinds the look found
/// something of: a read that failed is not an uninstall.
pub async fn retire_unseen(label: &str, seen: &HashSet<String>) {
    if seen.is_empty() || !graph::ready() {
        return;
    }
    let rows = match graph::query_all(&format!("MATCH (n:{label}) WHERE n.ended_ms IS NULL RETURN n.key ORDER BY n.key"), json!({})).await {
        Ok(rows) => rows,
        Err(error) => {
            tracing::info!("inventory: cannot read the stored {label} nodes: {error}");
            return;
        }
    };
    let gone: Vec<GraphRef> = rows.iter().map(|row| graph::text(&row[0])).filter(|key| !key.is_empty() && !seen.contains(key)).map(|key| r(label, key)).collect();
    if !gone.is_empty() {
        tracing::info!("inventory: {} {label} nodes are no longer on this Mac", gone.len());
        graph::retire(gone, "no longer on this Mac");
    }
}

/// Repositories whose folder is gone, or that are not a project (no git, no lockfiles).
pub async fn retire_gone_repos(seen: &HashSet<String>) {
    if !graph::ready() {
        return;
    }
    let Ok(rows) = graph::query_all("MATCH (n:Repo) WHERE n.ended_ms IS NULL RETURN n.key ORDER BY n.key", json!({})).await else { return };
    let gone: Vec<GraphRef> = rows
        .iter()
        .map(|row| graph::text(&row[0]))
        .filter(|key| {
            let root = Path::new(key);
            !key.is_empty() && !seen.contains(key) && (!root.is_dir() || !root.join(".git").exists())
        })
        .map(|key| r("Repo", key))
        .collect();
    if !gone.is_empty() {
        graph::retire(gone, "not a repository any more");
    }
}

struct BrowserExt {
    browser: &'static str,
    id: String,
    name: String,
    risky: Vec<&'static str>,
    all_sites: bool,
}

/// Which parts of the inventory to run; the sweep runs all of them.
#[derive(Clone, Copy, Default)]
pub struct Scope {
    /// macOS and Safari patch level, apps out of date, end-of-life runtimes.
    pub updates: bool,
    /// App signatures and dylib hijacking, browser and editor extensions, Docker images.
    pub apps: bool,
    /// Project lockfiles and venvs in OSV.
    pub deps: bool,
    /// Credentials in config files and projects' .env files.
    pub secrets: bool,
}

impl Scope {
    pub fn any(&self) -> bool {
        self.updates || self.apps || self.deps || self.secrets
    }
}

#[derive(Default)]
pub struct Local {
    pub part: Part,
    pub os: String,
    pub safari: String,
    pub apps: Vec<App>,
    pub casks_installed: HashSet<String>,
    toolchains: Vec<Toolchain>,
    pub projects: Vec<Project>,
    extensions: Vec<BrowserExt>,
}

fn info(path: &Path) -> Option<plist::Dictionary> {
    plist::Value::from_file(path).ok()?.into_dictionary()
}

fn text_of(dict: &plist::Dictionary, key: &str) -> String {
    dict.get(key).and_then(|v| v.as_string()).unwrap_or("").to_owned()
}

impl Local {
    /// What `scope` needs of this Mac. Blocking.
    pub fn gather(scope: Scope, discovery: &crate::filesystem::Discovery) -> Local {
        let mut local = Local {
            os: run("/usr/bin/sw_vers", &["-productVersion"], STEP).map(|o| o.stdout.trim().to_owned()).unwrap_or_default(),
            safari: info(Path::new("/Applications/Safari.app/Contents/Info.plist"))
                .map(|d| text_of(&d, "CFBundleShortVersionString"))
                .unwrap_or_default(),
            ..Default::default()
        };
        if scope.updates || scope.apps {
            local.apps(scope.apps, discovery);
        }
        if scope.updates {
            local.toolchains();
        }
        if scope.deps || scope.secrets {
            local.projects(discovery);
        }
        if scope.apps {
            local.extensions();
            editor_extensions(&mut local.part);
        }
        if scope.secrets {
            secret_files(&mut local.part, &local.projects);
        }
        discovery.report(&mut local.part);
        local
    }

    /// What an advisory is compared with: macOS and Safari, the apps (not inspected), the
    /// installed casks and the projects' packages. Blocking.
    pub fn installed() -> Local {
        let discovery = crate::filesystem::Discovery::scan();
        let mut local = Local::gather(Scope::default(), &discovery);
        local.apps(false, &discovery);
        local.projects(&discovery);
        local
    }

    /// The apps; `inspect` also checks their signatures and library loading (slower).
    fn apps(&mut self, inspect: bool, discovery: &crate::filesystem::Discovery) {
        let mut found: Vec<PathBuf> = discovery.apps.iter().cloned().collect();
        found.sort_by_key(|path| !path.starts_with(home()));
        for prefix in ["/opt/homebrew/Caskroom", "/usr/local/Caskroom"] {
            for entry in std::fs::read_dir(prefix).into_iter().flatten().flatten() {
                self.casks_installed.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
        let mut unsigned = Vec::new();
        let mut built = Vec::new();
        let mut hijack = Vec::new();
        let otool = inspect && run("/usr/bin/xcode-select", &["-p"], STEP).is_ok_and(|o| o.ok);
        for path in found {
            let Some(plist) = info(&path.join("Contents/Info.plist")) else { continue };
            let id = text_of(&plist, "CFBundleIdentifier");
            let mut version = text_of(&plist, "CFBundleShortVersionString");
            if version.is_empty() {
                version = text_of(&plist, "CFBundleVersion");
            }
            let name = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
            let feed = Some(text_of(&plist, "SUFeedURL")).filter(|f| f.starts_with("https://"));
            let origin = if path.join("Contents/_MASReceipt/receipt").exists() {
                "App Store"
            } else if id.starts_with("com.apple.") {
                "Apple"
            } else if feed.is_some() || path.join("Contents/Frameworks/Sparkle.framework").exists() {
                "Sparkle"
            } else {
                "direct"
            };
            let electron = info(&path.join("Contents/Frameworks/Electron Framework.framework/Resources/Info.plist"))
                .map(|d| text_of(&d, "CFBundleVersion"))
                .filter(|v| !v.is_empty());
            let mut signature = None;
            if inspect {
                let sig = codesign::check(&path);
                signature = Some((path.join("Contents/MacOS").join(text_of(&plist, "CFBundleExecutable")), sig.clone()));
                // Ad-hoc and never downloaded (no quarantine flag): built on this Mac.
                if sig.status == "adhoc" && xattr::get(&path, "com.apple.quarantine").ok().flatten().is_none() {
                    built.push(tilde(&path));
                } else if sig.unsigned() {
                    unsigned.push(format!("{} ({})", tilde(&path), if sig.status == "adhoc" { "ad-hoc signed" } else { "not signed" }));
                }
                if otool && sig.risky.iter().any(|r| r == "cs.disable-library-validation") {
                    let exe = path.join("Contents/MacOS").join(text_of(&plist, "CFBundleExecutable"));
                    let reasons = hijackable(&path, &exe);
                    if !reasons.is_empty() {
                        hijack.push(format!("{name} ({})", reasons.join("; ")));
                    }
                }
            }
            self.apps.push(App { name, id, version, path, origin, feed, electron, signature });
        }
        if !inspect {
            return;
        }
        self.part.checked.push("app signatures".into());
        if !unsigned.is_empty() {
            self.part.add(
                "medium",
                "app",
                format!(
                    "{} without a proper signature, so nobody vouches for {}: {}.",
                    plural(unsigned.len(), "app is", "apps are"),
                    if unsigned.len() == 1 { "it" } else { "them" },
                    names(&unsigned, 6)
                ),
                None,
                "codesign",
            );
        }
        if !built.is_empty() {
            self.part.add(
                "info",
                "app",
                format!("{} built on this Mac (ad-hoc signed, never downloaded): {}.", plural(built.len(), "app was", "apps were"), names(&built, 6)),
                None,
                "codesign",
            );
        }
        if otool {
            self.part.checked.push("dylib hijacking (apps that turn off library validation)".into());
        } else {
            self.part.skipped.push("dylib hijacking: needs otool from the Xcode command line tools".into());
        }
        if !hijack.is_empty() {
            self.part.add(
                "medium",
                "app",
                format!(
                    "{} off library validation and {} libraries from folders you can write to, so another program could slip code into {} (dylib hijacking): {}.",
                    plural(hijack.len(), "app turns", "apps turn"),
                    if hijack.len() == 1 { "loads" } else { "load" },
                    if hijack.len() == 1 { "it" } else { "them" },
                    names(&hijack, 4)
                ),
                None,
                "otool",
            );
        }
    }

    fn toolchains(&mut self) {
        let h = home();
        let mut list: Vec<Toolchain> = Vec::new();
        let mut add = |product: &'static str, label: &'static str, version: &str, place: &str| {
            let version = version.trim().trim_start_matches(['v', 'V']).trim_start_matches("go").to_owned();
            if numbers(&version).is_some() {
                list.push(Toolchain { product, label, version, place: place.to_owned() });
            }
        };
        let entries = |dir: PathBuf| -> Vec<String> {
            std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| !n.starts_with('.')).collect()
        };
        for name in entries(h.join(".pyenv/versions")) {
            add("python", "Python", &name, "pyenv");
        }
        for name in entries(h.join(".local/share/uv/python")) {
            // cpython-3.13.15-macos-aarch64-none
            if let Some(version) = name.strip_prefix("cpython-").and_then(|r| r.split('-').next()) {
                add("python", "Python", version, "uv");
            }
        }
        for name in entries(h.join(".nvm/versions/node")) {
            add("nodejs", "Node", &name, "nvm");
        }
        for dir in [h.join(".local/share/fnm/node-versions"), h.join("Library/Application Support/fnm/node-versions")] {
            for name in entries(dir) {
                add("nodejs", "Node", &name, "fnm");
            }
        }
        for name in entries(h.join(".volta/tools/image/node")) {
            add("nodejs", "Node", &name, "volta");
        }
        for name in entries(h.join(".rbenv/versions")) {
            add("ruby", "Ruby", &name, "rbenv");
        }
        for name in entries(h.join("sdk")) {
            if name.starts_with("go") {
                add("go", "Go", &name, "~/sdk");
            }
        }
        for (manager, base) in [("asdf", h.join(".asdf/installs")), ("mise", h.join(".local/share/mise/installs"))] {
            for (tool, product, label) in [
                ("python", "python", "Python"),
                ("nodejs", "nodejs", "Node"),
                ("node", "nodejs", "Node"),
                ("ruby", "ruby", "Ruby"),
                ("golang", "go", "Go"),
                ("go", "go", "Go"),
                ("postgres", "postgresql", "PostgreSQL"),
            ] {
                for name in entries(base.join(tool)) {
                    add(product, label, &name, manager);
                }
            }
        }
        // Homebrew: /opt/homebrew/opt/<formula> links to Cellar/<formula>/<version>.
        for opt in ["/opt/homebrew/opt", "/usr/local/opt"] {
            for name in entries(PathBuf::from(opt)) {
                let base = name.split('@').next().unwrap_or("");
                let (product, label) = match base {
                    "python" => ("python", "Python"),
                    "node" => ("nodejs", "Node"),
                    "ruby" => ("ruby", "Ruby"),
                    "go" => ("go", "Go"),
                    "postgresql" => ("postgresql", "PostgreSQL"),
                    _ => continue,
                };
                if let Ok(target) = std::fs::read_link(Path::new(opt).join(&name))
                    && let Some(version) = target.file_name()
                {
                    add(product, label, &version.to_string_lossy(), &format!("Homebrew {name}"));
                }
            }
        }
        for name in entries(PathBuf::from("/Applications/Postgres.app/Contents/Versions")) {
            add("postgresql", "PostgreSQL", &name, "Postgres.app");
        }
        for name in entries(PathBuf::from("/Library/Java/JavaVirtualMachines")) {
            let Ok(release) = std::fs::read_to_string(Path::new("/Library/Java/JavaVirtualMachines").join(&name).join("Contents/Home/release")) else {
                continue;
            };
            let field = |key: &str| {
                release.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim_start_matches('=').trim_matches('"').to_owned()).unwrap_or_default()
            };
            let vendor = field("IMPLEMENTOR");
            let product = match vendor.as_str() {
                "Eclipse Adoptium" => "eclipse-temurin",
                "Azul Systems, Inc." => "azul-zulu",
                "Amazon.com Inc." => "amazon-corretto",
                "Oracle Corporation" => "oracle-jdk",
                _ => continue,
            };
            add(product, "Java", &field("JAVA_VERSION"), &name);
        }
        let rust: Vec<String> =
            entries(h.join(".rustup/toolchains")).iter().map(|n| n.split('-').next().unwrap_or("").to_owned()).collect();
        if !rust.is_empty() {
            self.part.checked.push(format!("rustup toolchains ({})", rust.join(", ")));
        }
        list.sort_by(|a, b| (a.product, &a.version, &a.place).cmp(&(b.product, &b.version, &b.place)));
        list.dedup_by(|a, b| a.product == b.product && a.version == b.version && a.place == b.place);
        self.toolchains = list;
    }

    fn projects(&mut self, discovery: &crate::filesystem::Discovery) {
        let mut dirs = discovery.projects.clone();
        match places() {
            Ok(list) => dirs.extend(list.iter().map(PathBuf::from).filter(|p| p.is_dir())),
            Err(error) => self.part.skipped.push(format!("places from CortexTerm's Runs: {error}")),
        }
        let mut projects: BTreeMap<PathBuf, Project> = BTreeMap::new();
        for dir in dirs {
            let root = git_root(&dir).unwrap_or_else(|| dir.clone());
            let project = projects.entry(root.clone()).or_insert_with(|| Project { root: root.clone(), ..Default::default() });
            if dir.join("pyvenv.cfg").is_file() {
                read_venv(&dir, project, &mut self.toolchains);
            }
            // Discovery already visited every directory, including nested/hidden projects.
            // Read each directory once, grouping artifacts under its nearest repository.
            walk_project(&root, &dir, project, &mut self.part);
        }
        self.projects = projects.into_values().collect();
        self.projects.sort_by_key(|project| !project.root.starts_with(home()));
        let lockfiles: usize = self.projects.iter().map(|p| p.lockfiles.len()).sum();
        self.part.checked.push(format!("projects ({}, with {})", self.projects.len(), plural(lockfiles, "lockfile or venv", "lockfiles and venvs")));
    }

    fn extensions(&mut self) {
        let support = home().join("Library/Application Support");
        let browsers = [
            ("Chrome", "Google/Chrome"),
            ("Brave", "BraveSoftware/Brave-Browser"),
            ("Edge", "Microsoft Edge"),
            ("Arc", "Arc/User Data"),
            ("Vivaldi", "Vivaldi"),
            ("Chromium", "Chromium"),
        ];
        let mut seen = 0;
        for (browser, dir) in browsers {
            let root = support.join(dir);
            for profile in std::fs::read_dir(&root).into_iter().flatten().flatten() {
                let pname = profile.file_name().to_string_lossy().into_owned();
                if pname != "Default" && !pname.starts_with("Profile ") {
                    continue;
                }
                for ext in std::fs::read_dir(profile.path().join("Extensions")).into_iter().flatten().flatten() {
                    let id = ext.file_name().to_string_lossy().into_owned();
                    let Some(version_dir) = std::fs::read_dir(ext.path()).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_dir()).max() else {
                        continue;
                    };
                    let Ok(manifest) = std::fs::read(version_dir.join("manifest.json")).map(|b| serde_json::from_slice::<Value>(&b).unwrap_or_default()) else {
                        continue;
                    };
                    let mut perms: Vec<String> = Vec::new();
                    for key in ["permissions", "host_permissions"] {
                        perms.extend(manifest[key].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)));
                    }
                    for script in manifest["content_scripts"].as_array().into_iter().flatten() {
                        perms.extend(script["matches"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)));
                    }
                    let name = chrome_name(&version_dir, &manifest).unwrap_or_else(|| id.clone());
                    seen += 1;
                    self.extensions.push(browser_ext(browser, id, name, &perms));
                }
            }
        }
        for profile in std::fs::read_dir(support.join("Firefox/Profiles")).into_iter().flatten().flatten() {
            let Ok(list) = std::fs::read(profile.path().join("extensions.json")).map(|b| serde_json::from_slice::<Value>(&b).unwrap_or_default()) else {
                continue;
            };
            for addon in list["addons"].as_array().into_iter().flatten().filter(|a| a["location"] == "app-profile") {
                let mut perms: Vec<String> = Vec::new();
                for key in ["permissions", "origins"] {
                    perms.extend(addon["userPermissions"][key].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)));
                }
                let id = addon["id"].as_str().unwrap_or("").to_owned();
                let name = addon["defaultLocale"]["name"].as_str().map(str::to_owned).unwrap_or_else(|| id.clone());
                seen += 1;
                self.extensions.push(browser_ext("Firefox", id, name, &perms));
            }
        }
        self.part.checked.push(format!("browser extensions ({seen})"));
        match run("/usr/bin/pluginkit", &["-mAvvv", "-p", "com.apple.Safari.web-extension"], STEP) {
            Ok(out) => {
                let count = out.stdout.lines().filter(|l| l.trim_start().starts_with("Display Name")).count();
                self.part.checked.push(format!("Safari extensions ({count})"));
            }
            Err(error) => self.part.skipped.push(format!("Safari extensions: {error}")),
        }
    }
}

/// The app a browser's extensions live in.
fn browser_app(browser: &str) -> &'static str {
    match browser {
        "Chrome" => "com.google.Chrome",
        "Brave" => "com.brave.Browser",
        "Edge" => "com.microsoft.edgemac",
        "Arc" => "company.thebrowser.Browser",
        "Vivaldi" => "com.vivaldi.Vivaldi",
        "Chromium" => "org.chromium.Chromium",
        "Firefox" => "org.mozilla.firefox",
        _ => "",
    }
}

/// An extension's node key.
fn extension_key(ext: &BrowserExt) -> String {
    format!("{}:{}", ext.browser.to_lowercase(), ext.id)
}

/// Packages in one unit at most (with their repository and edges, under memory's 5000).
const PACKAGES_PER_UNIT: usize = 2000;

impl Local {
    /// What this look saw of the Mac, as graph units, parents first: macOS, the apps with their
    /// programs and signers, runtimes, repositories and their packages, browser extensions.
    /// Empty before memory answered.
    pub fn graph(&self) -> Batch {
        let mut batch = Batch::new();
        let Some(machine) = graph::machine() else { return batch };
        if !self.os.is_empty() {
            let unit = batch.unit();
            unit.node("OS", "macOS").t("version", self.os.clone());
            unit.edge(r("OS", "macOS"), "OF", machine.clone());
        }
        let mut apps = HashSet::new();
        for app in self.apps.iter().filter(|a| !a.id.is_empty()) {
            apps.insert(app.id.as_str());
            let unit = batch.unit();
            let node = unit.node("App", app.id.clone());
            node.p("name", app.name.clone()).p("origin", app.origin).p("path", app.path.display().to_string()).t("version", app.version.clone());
            node.po("electron", app.electron.clone());
            unit.edge(r("App", app.id.clone()), "INSTALLED_ON", machine.clone());
            if let Some((exe, sig)) = &app.signature {
                let key = exe.display().to_string();
                let binary = unit.node("Binary", key.clone());
                binary.p("signed", sig.status.clone()).p("apple", sig.apple).ps("team", &sig.team_id).ps("identifier", &sig.identifier);
                binary.po("notarized", sig.notarized).pl("risky", sig.risky.clone());
                unit.edge(r("App", app.id.clone()), "CONTAINS", r("Binary", key.clone()));
                if !sig.team_id.is_empty() {
                    unit.node("Signer", sig.team_id.clone()).ps("name", &sig.authority);
                    unit.edge(r("Binary", key), "SIGNED_BY", r("Signer", sig.team_id.clone()));
                }
            }
        }
        for tool in &self.toolchains {
            let key = format!("{}@{}", tool.product, tool.version);
            let unit = batch.unit();
            unit.node("Runtime", key.clone()).p("name", tool.label).p("product", tool.product).p("version", tool.version.clone());
            unit.edge(r("Runtime", key), "INSTALLED_ON", machine.clone()).p("place", tool.place.clone());
        }
        // A folder commands ran in is a project only when it is a git repository or has lockfiles.
        for project in self.projects.iter().filter(|p| p.is_project()) {
            let root = project.root.display().to_string();
            // name -> its versions in this repository.
            let mut versions: BTreeMap<(&str, &str), BTreeSet<&str>> = BTreeMap::new();
            for (eco, name, version) in &project.packages {
                versions.entry((eco, name.as_str())).or_default().insert(version.as_str());
            }
            let list: Vec<_> = versions.into_iter().collect();
            let mut first = true;
            for slice in list.chunks(PACKAGES_PER_UNIT).map(Some).chain(list.is_empty().then_some(None)) {
                let unit = batch.unit();
                unit.node("Repo", root.clone()).pl("lockfiles", project.lockfiles.clone());
                if first {
                    let folder = graph::folder(unit, &project.root);
                    unit.edge(r("Repo", root.clone()), "AT", folder);
                    first = false;
                }
                for ((eco, name), found) in slice.unwrap_or(&[]) {
                    let key = format!("{eco}:{name}");
                    unit.node("Package", key.clone()).p("ecosystem", *eco).p("name", *name);
                    let newest = found.iter().copied().max_by(|a, b| version_cmp(a, b).unwrap_or(Ordering::Equal)).unwrap_or("");
                    let edge = unit.edge(r("Repo", root.clone()), "DEPENDS_ON", r("Package", key));
                    edge.t("version", newest);
                    edge.pl("versions", if found.len() > 1 { found.iter().map(|v| v.to_string()).collect() } else { Vec::new() });
                }
            }
        }
        for ext in &self.extensions {
            let key = extension_key(ext);
            let unit = batch.unit();
            unit.node("Extension", key.clone()).p("name", ext.name.clone()).p("browser", ext.browser).pl("permissions", ext.risky.iter().map(|p| p.to_string()).collect::<Vec<_>>()).p("all_sites", ext.all_sites);
            let app = browser_app(ext.browser);
            if apps.contains(app) {
                unit.edge(r("Extension", key), "IN", r("App", app));
            } else {
                unit.edge(r("Extension", key), "ON", machine.clone());
            }
        }
        batch
    }
}

/// Homebrew's formulae and casks as installed: (name, newest installed version) each. Blocking.
pub fn homebrew() -> (Vec<(String, String)>, Vec<(String, String)>) {
    let newest = |dir: PathBuf| -> Option<String> {
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with('.'))
            .max_by(|a, b| crate::cve::loose_cmp(a, b).unwrap_or(Ordering::Equal))
    };
    let mut formulae = Vec::new();
    let mut casks = Vec::new();
    for prefix in ["/opt/homebrew", "/usr/local"] {
        for (folder, list) in [("Cellar", &mut formulae), ("Caskroom", &mut casks)] {
            for entry in std::fs::read_dir(Path::new(prefix).join(folder)).into_iter().flatten().flatten() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if let Some(version) = newest(entry.path()) {
                    list.push((name, version));
                }
            }
        }
    }
    (formulae, casks)
}

/// Homebrew's formulae and casks as `(:Formula {key: name, kind, version*})-[:INSTALLED_ON]->(:Machine)`.
pub fn homebrew_graph(formulae: &[(String, String)], casks: &[(String, String)]) -> Batch {
    let mut batch = Batch::new();
    let Some(machine) = graph::machine() else { return batch };
    for (kind, list) in [("formula", formulae), ("cask", casks)] {
        for (name, version) in list {
            let unit = batch.unit();
            unit.node("Formula", name.clone()).p("kind", kind).t("version", version.clone());
            unit.edge(r("Formula", name.clone()), "INSTALLED_ON", machine.clone());
        }
    }
    batch
}

/// Global npm, pipx and cargo tools as `(:Package)-[:INSTALLED_ON {version*, manager}]->(:Machine)`.
pub fn tools_graph(tools: &[crate::sweep::Package]) -> Batch {
    let mut batch = Batch::new();
    let Some(machine) = graph::machine() else { return batch };
    for tool in tools {
        let key = format!("{}:{}", tool.ecosystem, tool.name);
        let unit = batch.unit();
        unit.node("Package", key.clone()).p("ecosystem", tool.ecosystem).p("name", tool.name.clone());
        unit.edge(r("Package", key), "INSTALLED_ON", machine.clone()).p("manager", tool.manager).t("version", tool.version.clone());
    }
    batch
}

/// The folders terminal commands ran in, `(:CommandRun)-[:IN]->(:Folder)`, and the repositories
/// the graph knows (`(:Repo)`). Blocking.
fn places() -> Result<Vec<String>, String> {
    if !graph::ready() {
        return Err("memory is not reachable yet".into());
    }
    let read = async {
        let mut out: Vec<String> = Vec::new();
        for cypher in [
            "MATCH (:CommandRun)-[:IN]->(f:Folder) RETURN DISTINCT f.key ORDER BY f.key",
            "MATCH (r:Repo) WHERE r.state IS NULL OR r.state <> 'gone' RETURN r.key ORDER BY r.key",
        ] {
            out.extend(graph::query_all(cypher, json!({})).await?.iter().map(|row| graph::text(&row[0])).filter(|p| !p.is_empty()));
        }
        Ok(out)
    };
    graph::block(read).unwrap_or_else(|| Err("no async runtime".into()))
}

fn git_root(path: &Path) -> Option<PathBuf> {
    path.ancestors().find(|p| p.join(".git").exists()).map(Path::to_path_buf)
}

/// Read artifacts in one directory from the complete filesystem discovery.
fn walk_project(root: &Path, dir: &Path, project: &mut Project, part: &mut Part) {
    let read = match std::fs::read_dir(dir) {
        Ok(read) => read,
        Err(error) => {
            part.skipped.push(format!("project files in {}: {error}", tilde(dir)));
            return;
        }
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = std::fs::metadata(&path) else { continue };
        if !meta.is_file() {
            continue;
        }
        if name.starts_with(".env") && !["example", "sample", "template", "dist", "defaults"].iter().any(|s| name.contains(s)) {
            project.envs.push(path);
            continue;
        }
        let parser: fn(&str, &mut BTreeSet<(&'static str, String, String)>) = match name.as_str() {
            "package-lock.json" | "npm-shrinkwrap.json" => npm_lock,
            "pnpm-lock.yaml" => pnpm_lock,
            "Cargo.lock" => |t, out| toml_lock(t, "crates.io", out),
            "poetry.lock" | "uv.lock" => |t, out| toml_lock(t, "PyPI", out),
            "Gemfile.lock" => gem_lock,
            "go.mod" => go_mod,
            n if n.starts_with("requirements") && n.ends_with(".txt") => requirements,
            _ => continue,
        };
        if entry.metadata().is_ok_and(|m| m.len() > 30 * 1024 * 1024) {
            part.skipped.push(format!("dependency file {}: larger than 30 MiB", tilde(&path)));
            continue;
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => {
                parser(&text, &mut project.packages);
                project.lockfiles.push(path.strip_prefix(root).unwrap_or(&path).display().to_string());
            }
            Err(error) => part.skipped.push(format!("dependency file {}: {error}", tilde(&path))),
        }
    }
}

fn read_venv(venv: &Path, project: &mut Project, toolchains: &mut Vec<Toolchain>) {
    if let Ok(cfg) = std::fs::read_to_string(venv.join("pyvenv.cfg"))
        && let Some(version) = cfg.lines().find_map(|l| {
            let (key, value) = l.split_once('=')?;
            matches!(key.trim(), "version" | "version_info").then(|| value.trim().to_owned())
        })
    {
        toolchains.push(Toolchain { product: "python", label: "Python", version, place: format!("venv {}", tilde(venv)) });
    }
    for lib in std::fs::read_dir(venv.join("lib")).into_iter().flatten().flatten() {
        for dist in std::fs::read_dir(lib.path().join("site-packages")).into_iter().flatten().flatten() {
            let name = dist.file_name().to_string_lossy().into_owned();
            if let Some((package, version)) = name.strip_suffix(".dist-info").and_then(|n| n.rsplit_once('-')) {
                project.packages.insert(("PyPI", package.to_owned(), version.to_owned()));
            }
        }
    }
    project.lockfiles.push(format!("{} (venv)", venv.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
}

type Packages = BTreeSet<(&'static str, String, String)>;

fn npm_lock(text: &str, out: &mut Packages) {
    let Ok(lock) = serde_json::from_str::<Value>(text) else { return };
    if let Some(packages) = lock["packages"].as_object() {
        for (key, info) in packages {
            let Some(path_name) = key.rsplit_once("node_modules/").map(|(_, n)| n) else { continue };
            if info["link"] == true {
                continue;
            }
            let name = info["name"].as_str().unwrap_or(path_name);
            if let Some(version) = info["version"].as_str() {
                out.insert(("npm", name.to_owned(), version.to_owned()));
            }
        }
    } else {
        fn deps(node: &Value, out: &mut Packages) {
            for (name, info) in node["dependencies"].as_object().into_iter().flatten() {
                if let Some(version) = info["version"].as_str() {
                    out.insert(("npm", name.clone(), version.to_owned()));
                }
                deps(info, out);
            }
        }
        deps(&lock, out);
    }
}

/// pnpm 5 (`/name/1.0.0:`), 6 (`/name@1.0.0:`) and 9 (`name@1.0.0:`), only the `packages:` section.
fn pnpm_lock(text: &str, out: &mut Packages) {
    let Ok(line_re) = Regex::new(r"^  '?/?((?:@[^/@\s']+/)?[^/@\s('\x22]+)[@/](\d[^(:'\x22\s]*)") else { return };
    let mut inside = false;
    for line in text.lines() {
        if !line.starts_with(' ') && !line.is_empty() {
            inside = line.starts_with("packages:");
            continue;
        }
        if inside && let Some(c) = line_re.captures(line) {
            out.insert(("npm", c[1].to_owned(), c[2].to_owned()));
        }
    }
}

/// `[[package]]` blocks of Cargo.lock, poetry.lock and uv.lock; only registry packages.
fn toml_lock(text: &str, ecosystem: &'static str, out: &mut Packages) {
    let mut flush = |name: &mut String, version: &mut String, local: &mut bool| {
        if !name.is_empty() && !version.is_empty() && !*local {
            out.insert((ecosystem, std::mem::take(name), std::mem::take(version)));
        }
        name.clear();
        version.clear();
        *local = false;
    };
    let (mut name, mut version, mut local, mut sourced) = (String::new(), String::new(), false, false);
    let value = |line: &str| line.split_once('=').map(|(_, v)| v.trim().trim_matches('"').to_owned()).unwrap_or_default();
    for line in text.lines() {
        let line = line.trim();
        if line == "[[package]]" {
            // Cargo.lock: a crate with no `source` is part of the workspace.
            if ecosystem == "crates.io" && !sourced {
                local = true;
            }
            flush(&mut name, &mut version, &mut local);
            sourced = false;
        } else if line.starts_with("name =") && name.is_empty() {
            name = value(line);
        } else if line.starts_with("version =") && version.is_empty() {
            version = value(line);
        } else if line.starts_with("source =") {
            sourced = true;
            if ["git+", "git =", "editable", "virtual", "path =", "path+", "directory ="].iter().any(|s| line.contains(s)) {
                local = true;
            }
        } else if line.starts_with("type =") && ["git", "directory", "file", "url"].contains(&value(line).as_str()) {
            local = true;
        }
    }
    if ecosystem == "crates.io" && !sourced {
        local = true;
    }
    flush(&mut name, &mut version, &mut local);
}

fn gem_lock(text: &str, out: &mut Packages) {
    let mut inside = false;
    for line in text.lines() {
        if !line.starts_with(' ') {
            inside = line == "GEM";
            continue;
        }
        // Exactly four spaces: a gem, deeper lines are its dependencies.
        if inside
            && line.starts_with("    ")
            && !line.starts_with("     ")
            && let Some((name, rest)) = line.trim().split_once(" (")
        {
            let version = rest.trim_end_matches(')').split('-').next().unwrap_or("");
            out.insert(("RubyGems", name.to_owned(), version.to_owned()));
        }
    }
}

fn go_mod(text: &str, out: &mut Packages) {
    let mut block = false;
    for line in text.lines() {
        let line = line.split("//").next().unwrap_or("").trim();
        let spec = if block {
            if line == ")" {
                block = false;
                continue;
            }
            line
        } else if line == "require (" {
            block = true;
            continue;
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest
        } else {
            continue;
        };
        if let Some((module, version)) = spec.split_once(' ') {
            out.insert(("Go", module.to_owned(), version.trim().trim_start_matches('v').trim_end_matches("+incompatible").to_owned()));
        }
    }
}

fn requirements(text: &str, out: &mut Packages) {
    for line in text.lines() {
        let line = line.split(['#', ';']).next().unwrap_or("").trim();
        if let Some((name, version)) = line.split_once("==") {
            let name = name.split('[').next().unwrap_or("").trim();
            let version = version.split(',').next().unwrap_or("").trim();
            if !name.is_empty() && !version.is_empty() && !name.starts_with('-') {
                out.insert(("PyPI", name.to_owned(), version.to_owned()));
            }
        }
    }
}

/// Library search paths and weak libraries of an app's executable that point outside the app
/// into folders the user can write to (Objective-See's DHS idea, the simple version).
fn hijackable(app: &Path, exe: &Path) -> Vec<String> {
    let Ok(out) = run("/usr/bin/otool", &["-l", &exe.display().to_string()], STEP) else { return Vec::new() };
    let dir = exe.parent().unwrap_or(app).display().to_string();
    let resolve = |p: &str| PathBuf::from(p.replace("@executable_path", &dir).replace("@loader_path", &dir));
    let (mut rpaths, mut weak) = (Vec::new(), Vec::new());
    let mut cmd = "";
    for line in out.stdout.lines() {
        let line = line.trim();
        if let Some(c) = line.strip_prefix("cmd ") {
            cmd = c;
        } else if let Some(value) = line.strip_prefix("path ").filter(|_| cmd == "LC_RPATH") {
            rpaths.push(resolve(value.split(" (offset").next().unwrap_or(value)));
        } else if let Some(value) = line.strip_prefix("name ").filter(|_| cmd == "LC_LOAD_WEAK_DYLIB") {
            weak.push(value.split(" (offset").next().unwrap_or(value).to_owned());
        }
    }
    let outside = |p: &Path| !p.starts_with(app);
    let mut reasons = BTreeSet::new();
    for rpath in &rpaths {
        if outside(rpath) && writable(rpath) {
            reasons.insert(format!("searches {}", tilde(rpath)));
        }
    }
    for lib in &weak {
        let candidates: Vec<PathBuf> = match lib.strip_prefix("@rpath/") {
            Some(rest) => rpaths.iter().map(|r| r.join(rest)).collect(),
            None => vec![resolve(lib)],
        };
        if !candidates.iter().any(|c| c.exists())
            && let Some(first) = candidates.first()
            && outside(first)
            && writable(first)
        {
            reasons.insert(format!("would load the missing {}", tilde(first)));
        }
    }
    reasons.into_iter().collect()
}

/// The user can write to it, or create it (the nearest existing folder is writable).
fn writable(path: &Path) -> bool {
    let Some(existing) = path.ancestors().find(|p| p.exists()) else { return false };
    let Ok(c) = std::ffi::CString::new(existing.as_os_str().as_bytes()) else { return false };
    // SAFETY: a valid NUL-terminated path.
    unsafe { libc::access(c.as_ptr(), libc::W_OK) == 0 }
}

fn chrome_name(dir: &Path, manifest: &Value) -> Option<String> {
    let name = manifest["name"].as_str()?;
    let Some(key) = name.strip_prefix("__MSG_").and_then(|k| k.strip_suffix("__")) else { return Some(name.to_owned()) };
    let locale = manifest["default_locale"].as_str().unwrap_or("en");
    let messages: Value = serde_json::from_slice(&std::fs::read(dir.join("_locales").join(locale).join("messages.json")).ok()?).ok()?;
    messages.as_object()?.iter().find(|(k, _)| k.eq_ignore_ascii_case(key)).and_then(|(_, v)| v["message"].as_str().map(str::to_owned))
}

fn browser_ext(browser: &'static str, id: String, name: String, perms: &[String]) -> BrowserExt {
    let all_sites = perms.iter().any(|p| matches!(p.as_str(), "<all_urls>" | "*://*/*" | "http://*/*" | "https://*/*" | "*://*/") || p.starts_with("*://*/"));
    let risky = [
        ("cookies", "cookies"),
        ("debugger", "the debugger"),
        ("clipboardRead", "the clipboard"),
        ("nativeMessaging", "programs on the Mac (native messaging)"),
        ("webRequestBlocking", "blocking web requests"),
        ("proxy", "the proxy"),
        ("management", "other extensions"),
    ]
    .into_iter()
    .filter(|(perm, _)| perms.iter().any(|p| p == perm))
    .map(|(_, what)| what)
    .collect();
    BrowserExt { browser, id, name, risky, all_sites }
}

/// VS Code, Cursor and Windsurf extensions: run on every start, sideloaded, invisible code.
fn editor_extensions(part: &mut Part) {
    let h = home();
    let editors = [
        ("VS Code", "code", h.join(".vscode/extensions")),
        ("VS Code Insiders", "code-insiders", h.join(".vscode-insiders/extensions")),
        ("Cursor", "cursor", h.join(".cursor/extensions")),
        ("Windsurf", "windsurf", h.join(".windsurf/extensions")),
        ("VSCodium", "codium", h.join(".vscode-oss/extensions")),
    ];
    if editors.iter().all(|(_, _, dir)| !dir.is_dir()) {
        part.skipped.push("editor extensions: no VS Code, Cursor or Windsurf extensions folder".into());
        return;
    }
    for (editor, cli, dir) in editors {
        if !dir.is_dir() {
            continue;
        }
        let sources: HashMap<String, String> = std::fs::read(dir.join("extensions.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
            .and_then(|v| v.as_array().cloned())
            .into_iter()
            .flatten()
            .filter_map(|e| Some((e["identifier"]["id"].as_str()?.to_lowercase(), e["metadata"]["source"].as_str()?.to_owned())))
            .collect();
        let (mut count, mut always, mut sideloaded) = (0, Vec::new(), Vec::new());
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let Some(pkg) = std::fs::read(path.join("package.json")).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()) else { continue };
            count += 1;
            let id = format!("{}.{}", pkg["publisher"].as_str().unwrap_or("?"), pkg["name"].as_str().unwrap_or("?"));
            let version = pkg["version"].as_str().unwrap_or("");
            if pkg["activationEvents"].as_array().is_some_and(|a| a.iter().any(|e| e == "*")) {
                always.push(id.clone());
            }
            if sources.get(&id.to_lowercase()).is_some_and(|s| s == "vsix") {
                sideloaded.push(id.clone());
            }
            for main in ["main", "browser"].iter().filter_map(|k| pkg[*k].as_str()) {
                let mut file = path.join(main);
                if !file.is_file() {
                    file = path.join(format!("{main}.js"));
                }
                let hidden = invisible_run(&file);
                if hidden >= 10 {
                    part.add(
                        "high",
                        "app",
                        format!(
                            "The {editor} extension {id} {version} hides a run of {hidden} invisible characters in its code ({}), the trick GlassWorm used to smuggle in malware. Remove it.",
                            tilde(&file)
                        ),
                        Some(format!("{cli} --uninstall-extension {id}")),
                        "editor extensions",
                    );
                    break;
                }
            }
        }
        part.checked.push(format!("{editor} extensions ({count})"));
        if !always.is_empty() {
            part.add(
                "info",
                "app",
                format!("{} start every time {editor} opens (activation \"*\"): {}.", plural(always.len(), "extension", "extensions"), names(&always, 8)),
                None,
                "editor extensions",
            );
        }
        if !sideloaded.is_empty() {
            part.add(
                "low",
                "app",
                format!("{} in {editor} came from a .vsix file, not a marketplace: {}.", plural(sideloaded.len(), "extension", "extensions"), names(&sideloaded, 8)),
                None,
                "editor extensions",
            );
        }
    }
}

/// The longest run of invisible characters (zero-width, variation selectors, tags, private use)
/// in a file of at most 8 MB.
fn invisible_run(path: &Path) -> usize {
    if std::fs::metadata(path).map(|m| m.len()).unwrap_or(u64::MAX) > 8 * 1024 * 1024 {
        return 0;
    }
    let Ok(bytes) = std::fs::read(path) else { return 0 };
    let (mut best, mut current) = (0, 0);
    for c in String::from_utf8_lossy(&bytes).chars() {
        let hidden = matches!(c as u32,
            0x200B..=0x200F | 0x2060..=0x2064 | 0xFEFF | 0xFE00..=0xFE0F | 0xE000..=0xF8FF | 0xE0000..=0xE007F | 0xE0100..=0xE01EF | 0xF0000..=0x10FFFF);
        current = if hidden { current + 1 } else { 0 };
        best = best.max(current);
    }
    best
}

/// Credentials in the usual config files and .env files of known projects: counts and places.
fn secret_files(part: &mut Part, projects: &[Project]) {
    let h = home();
    let shared = secret_patterns();
    let files: [(&str, &str); 6] = [
        (".npmrc", r"(?m)^\s*(?://\S+:)?_(?:authToken|auth|password)\s*=\s*\S+"),
        (".pypirc", r"(?m)^\s*password\s*[=:]\s*\S+"),
        (".aws/credentials", r"(?m)^\s*aws_secret_access_key\s*=\s*\S+"),
        (".netrc", r"\bpassword\s+\S+"),
        (".git-credentials", r"(?m)^\w+://[^:\s/]+:[^@\s]+@"),
        (".config/gh/hosts.yml", r"(?m)^\s*oauth_token:\s*\S+"),
    ];
    let (mut found, mut open) = (Vec::new(), Vec::new());
    for (file, pattern) in files {
        let path = h.join(file);
        let Ok(text) = std::fs::read_to_string(&path) else { continue };
        let Ok(re) = Regex::new(pattern) else { continue };
        let lines = text.lines().filter(|l| re.is_match(l) || shared.iter().any(|(_, s)| s.is_match(l))).count();
        if lines > 0 {
            found.push(format!("~/{file} ({lines})"));
            if std::fs::metadata(&path).is_ok_and(|m| m.permissions().mode() & 0o044 != 0) {
                open.push(format!("~/{file}"));
            }
        }
    }
    // Docker: an `auth` value in `auths` is the registry password, base64-encoded.
    if let Ok(config) = std::fs::read(h.join(".docker/config.json")).map(|b| serde_json::from_slice::<Value>(&b).unwrap_or_default()) {
        let registries: Vec<String> = config["auths"]
            .as_object()
            .into_iter()
            .flatten()
            .filter(|(_, v)| v["auth"].as_str().is_some_and(|a| !a.is_empty()) || v["identitytoken"].as_str().is_some_and(|a| !a.is_empty()))
            .map(|(k, _)| k.clone())
            .collect();
        if !registries.is_empty() {
            part.add(
                "medium",
                "secret",
                format!(
                    "~/.docker/config.json keeps the password for {} in plain text ({}); a credential helper keeps it in the keychain.",
                    plural(registries.len(), "registry", "registries"),
                    names(&registries, 4)
                ),
                Some(registries.iter().map(|r| format!("docker logout {r}")).collect::<Vec<_>>().join(" && ")),
                "docker config",
            );
        }
    }
    part.checked.push("credentials in config files".into());
    if !found.is_empty() {
        part.add(
            "medium",
            "secret",
            format!(
                "Credentials sit in plain text in {}: {}. Malware that runs as you collects these files first; prefer the keychain or short-lived tokens.",
                plural(found.len(), "file", "files"),
                found.join(", ")
            ),
            None,
            "config files",
        );
    }
    if !open.is_empty() {
        part.add(
            "high",
            "secret",
            format!("Other users of this Mac can read {}, which holds credentials.", open.join(", ")),
            Some(format!("chmod 600 {}", open.join(" "))),
            "config files",
        );
    }
    let Ok(env_re) = Regex::new(
        r"(?i)^\s*(?:export\s+)?[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIALS?)[A-Z0-9_]*\s*=\s*['\x22]?[^\s'\x22#]{8,}",
    ) else {
        return;
    };
    let mut envs = Vec::new();
    for path in projects.iter().flat_map(|p| &p.envs) {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(error) => {
                part.skipped.push(format!("secrets in {}: {error}", tilde(path)));
                continue;
            }
        };
        let lines = text.lines().filter(|l| env_re.is_match(l) || shared.iter().any(|(_, s)| s.is_match(l))).count();
        if lines > 0 {
            envs.push(format!("{} ({lines})", tilde(path)));
        }
    }
    part.checked.push(".env files in projects".into());
    if !envs.is_empty() {
        part.add(
            "low",
            "secret",
            format!(
                "{} in your projects {} secrets: {}. Keep them out of git and out of reach of install scripts.",
                plural(envs.len(), ".env file", ".env files"),
                if envs.len() == 1 { "holds" } else { "hold" },
                names(&envs, 6)
            ),
            None,
            ".env files",
        );
    }
}

// ---------------------------------------------------------------------------------------------
// The checks

async fn limited(label: &str, seconds: u64, work: impl Future<Output = Part>) -> Part {
    match tokio::time::timeout(Duration::from_secs(seconds), work).await {
        Ok(part) => part,
        Err(_) => Part { skipped: vec![format!("{label}: no answer within {seconds} s")], ..Default::default() },
    }
}

async fn when(wanted: bool, work: impl Future<Output = Part>) -> Part {
    if wanted { work.await } else { Part::default() }
}

/// The inventory checks `scope` asks for; full checks wait for filesystem discovery.
pub async fn checks(scope: Scope, discovery: crate::filesystem::Shared) -> Part {
    let mut part = Part::default();
    if !cfg!(target_os = "macos") {
        part.skipped.push("installed software: not a Mac".into());
        return part;
    }
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(40))
        .connect_timeout(Duration::from_secs(10))
        .user_agent("CortexTerm-security-check")
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            part.skipped.push(format!("installed software: {error}"));
            return part;
        }
    };
    let gathering = crate::util::background(move || {
        let found = discovery.get();
        if discovery.is_cancelled() { return Local::default(); }
        Local::gather(scope, found)
    });
    let (feeds, notes) = match tokio::time::timeout(Duration::from_secs(50), load_feeds(&client)).await {
        Ok(loaded) => loaded,
        Err(_) => {
            // Offline or slow: whatever is cached.
            let offline = reqwest::Client::builder().timeout(Duration::from_millis(1)).build().unwrap_or_default();
            load_feeds(&offline).await
        }
    };
    part.merge(notes);
    let local = match gathering.await {
        Some(local) => local,
        None => {
            part.skipped.push("installed software: filesystem discovery failed".into());
            return part;
        }
    };
    // What is installed goes to the graph first, so the findings below can point at it; what is
    // not any more is marked gone.
    part.graph.extend(local.graph());
    if scope.updates {
        retire_unseen("Runtime", &local.toolchains.iter().map(|t| format!("{}@{}", t.product, t.version)).collect()).await;
    }
    if scope.apps {
        retire_unseen("Extension", &local.extensions.iter().map(extension_key).collect()).await;
    }
    let (apps, os, eol, deps, docker) = tokio::join!(
        when(scope.updates, apps_section(&client, &feeds, &local)),
        when(scope.updates, limited("macOS and Safari patch level", 30, os_section(&client, &feeds, &local))),
        when(scope.updates, eol_section(&client, &local)),
        when(scope.deps, deps_section(&client, &feeds, &local)),
        when(scope.apps, async { tokio::task::spawn_blocking(docker_checks).await.unwrap_or_default() }),
    );
    for each in [apps, os, eol, deps, docker] {
        part.merge(each);
    }
    if scope.apps {
        part.merge(extension_findings(&feeds, &local));
    }
    let Local { part: found, .. } = local;
    part.merge(found);
    part
}

/// Out-of-date apps (App Store, Homebrew catalogue, Sparkle feed), browsers against their vendor,
/// and Electron apps on an Electron that no longer gets fixes.
async fn apps_section(client: &reqwest::Client, feeds: &Feeds, local: &Local) -> Part {
    let mut part = Part::default();
    let apps = &local.apps;
    let mut by_name: HashMap<String, usize> = HashMap::new();
    let mut by_id: HashMap<&str, usize> = HashMap::new();
    for (i, cask) in feeds.casks.iter().enumerate() {
        for app in &cask.apps {
            by_name.entry(app.clone()).or_insert(i);
        }
        for id in &cask.ids {
            by_id.entry(id.as_str()).or_insert(i);
        }
    }
    let browsers = ["com.google.Chrome", "org.mozilla.firefox"];
    let mut latest: Vec<Option<(String, &str)>> = vec![None; apps.len()];
    let mut origin: Vec<&str> = apps.iter().map(|a| a.origin).collect();

    // The App Store, 20 bundle ids per request.
    let store: Vec<usize> = (0..apps.len()).filter(|&i| apps[i].origin == "App Store").collect();
    for chunk in store.chunks(20) {
        let ids = chunk.iter().map(|&i| apps[i].id.as_str()).collect::<Vec<_>>().join(",");
        match get(client, &format!("https://itunes.apple.com/lookup?bundleId={ids}")).await.and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|e| e.to_string())) {
            Ok(answer) => {
                for result in answer["results"].as_array().into_iter().flatten() {
                    if let (Some(id), Some(version)) = (result["bundleId"].as_str(), result["version"].as_str())
                        && let Some(&i) = chunk.iter().find(|&&i| apps[i].id == id)
                    {
                        latest[i] = Some((version.to_owned(), "App Store"));
                    }
                }
            }
            Err(error) => {
                part.skipped.push(format!("App Store versions: {error}"));
                break;
            }
        }
    }
    if !store.is_empty() {
        part.checked.push("App Store app versions".into());
    }

    // The Homebrew cask catalogue knows most other apps, installed through brew or not.
    for (i, app) in apps.iter().enumerate() {
        if app.origin == "App Store" || app.origin == "Apple" || browsers.contains(&app.id.as_str()) {
            continue;
        }
        let file = format!("{}.app", app.name).to_lowercase();
        let Some(&c) = by_id.get(app.id.as_str()).or_else(|| by_name.get(&file)) else { continue };
        let cask = &feeds.casks[c];
        if local.casks_installed.contains(&cask.token) {
            origin[i] = "Homebrew";
        }
        let version = cask.version.split(',').next().unwrap_or("");
        if numbers(version).is_some() {
            latest[i] = Some((version.to_owned(), "Homebrew catalogue"));
        }
    }
    if !feeds.casks.is_empty() {
        part.checked.push("app versions (Homebrew cask catalogue)".into());
    }

    // Bound concurrency, not coverage: visit every remaining app with a Sparkle feed.
    let pending: Vec<usize> = apps.iter().enumerate().filter(|(i, _)| latest[*i].is_none()).map(|(i, _)| i).collect();
    let mut sparkle = 0;
    for chunk in pending.chunks(20) {
        let mut tasks = tokio::task::JoinSet::new();
        for &i in chunk {
            if let Some(url) = apps[i].feed.clone() {
                let client = client.clone();
                tasks.spawn(async move {
                    let bytes = tokio::time::timeout(Duration::from_secs(15), get(&client, &url)).await.ok()?.ok()?;
                    Some((i, sparkle_latest(&String::from_utf8_lossy(&bytes))?))
                });
            }
        }
        while let Some(done) = tasks.join_next().await {
            if let Ok(Some((i, version))) = done {
                latest[i] = Some((version, "Sparkle feed"));
                sparkle += 1;
            }
        }
    }
    if sparkle > 0 {
        part.checked.push(format!("app versions (Sparkle feeds, {sparkle})"));
    }

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for o in &origin {
        *counts.entry(o).or_default() += 1;
    }
    part.checked.push(format!(
        "apps ({}: {})",
        apps.len(),
        counts.iter().map(|(o, n)| format!("{n} {o}")).collect::<Vec<_>>().join(", ")
    ));

    // Out of date, one finding per way of updating.
    let mut groups: BTreeMap<&str, Vec<(usize, String)>> = BTreeMap::new();
    for (i, app) in apps.iter().enumerate() {
        if let Some((version, _)) = &latest[i]
            && newer(version, &app.version)
        {
            let group = match origin[i] {
                "App Store" => "App Store",
                "Homebrew" => "Homebrew",
                _ => "other",
            };
            groups.entry(group).or_default().push((i, format!("{} {} → {}", app.name, app.version, version)));
        }
    }
    for (group, list) in groups {
        let shown: Vec<String> = list.iter().map(|(_, s)| s.clone()).collect();
        let (fix, how) = match group {
            "App Store" => (Some("open macappstore://showUpdatesPage".to_owned()), "from the App Store"),
            "Homebrew" => {
                let tokens: Vec<String> = list
                    .iter()
                    .filter_map(|(i, _)| by_name.get(&format!("{}.app", apps[*i].name).to_lowercase()).or_else(|| by_id.get(apps[*i].id.as_str())))
                    .map(|&c| feeds.casks[c].token.clone())
                    .collect();
                (Some(format!("brew upgrade --cask {}", tokens.join(" "))), "with Homebrew")
            }
            _ => (None, "from each app's Check for Updates menu"),
        };
        part.add(
            "low",
            "outdated",
            format!("{} out of date: {}. Update {how}.", plural(list.len(), "app is", "apps are"), names(&shown, 8)),
            fix,
            "app versions",
        );
        if let [(i, _)] = list.as_slice() {
            part.about("App", apps[*i].id.clone());
        }
    }

    // Chrome and Firefox against their vendor's current release.
    for app in apps.iter().filter(|a| browsers.contains(&a.id.as_str())) {
        let current = if app.id == "com.google.Chrome" {
            feeds.chrome.clone()
        } else {
            feeds.firefox.as_ref().and_then(|f| {
                let esr = f["FIREFOX_ESR"].as_str().unwrap_or("");
                let release = f["LATEST_FIREFOX_VERSION"].as_str().unwrap_or("");
                let current = if major(esr) == major(&app.version) { esr } else { release };
                Some(current.trim_end_matches("esr").to_owned()).filter(|v| !v.is_empty())
            })
        };
        let Some(current) = current else {
            part.skipped.push(format!("{} version: the vendor's current version is unknown", app.name));
            continue;
        };
        part.checked.push(format!("{} version", app.name));
        if newer(&current, &app.version) {
            part.add(
                "medium",
                "outdated",
                format!("{} {} is behind the current {current}; browser updates often fix bugs that are already being exploited. Restart it to finish updating.", app.name, app.version),
                None,
                "vendor versions",
            );
            part.about("App", app.id.clone());
        }
    }

    // Electron apps: supported Electron is the newest three majors.
    match &feeds.electron {
        None => part.skipped.push("Electron apps: no Electron release list".into()),
        Some(index) => {
            let chrome_now = feeds.chrome.as_deref().and_then(major).or_else(|| index.chrome.get(&index.stable).and_then(|c| major(c)));
            let mut old = Vec::new();
            let mut old_ids: Vec<String> = Vec::new();
            for app in apps {
                let Some(version) = &app.electron else { continue };
                let Some(m) = major(version) else { continue };
                if m + 2 < index.stable {
                    let chromium = index.chrome.get(&m).and_then(|c| major(c));
                    let behind = match (chromium, chrome_now) {
                        (Some(c), Some(now)) if now > c => format!(", Chromium {c}, {} versions behind Chrome", now - c),
                        (Some(c), _) => format!(", Chromium {c}"),
                        _ => String::new(),
                    };
                    old.push(format!("{} (Electron {version}{behind})", app.name));
                    old_ids.push(app.id.clone());
                }
            }
            part.checked.push(format!("Electron apps ({})", apps.iter().filter(|a| a.electron.is_some()).count()));
            if !old.is_empty() {
                part.add(
                    "medium",
                    "app",
                    format!(
                        "{} on an Electron version that no longer gets security fixes (current is Electron {}), so the browser engine inside lags Chrome: {}.",
                        plural(old.len(), "app is built", "apps are built"),
                        index.stable,
                        names(&old, 6)
                    ),
                    None,
                    "electron",
                );
                if let [id] = old_ids.as_slice() {
                    part.about("App", id.clone());
                }
            }
        }
    }
    part
}

/// The newest stable version a Sparkle appcast offers (items on a beta channel left out).
fn sparkle_latest(xml: &str) -> Option<String> {
    let short = Regex::new(r#"sparkle:shortVersionString(?:="([^"]+)"|>([^<]+)<)"#).ok()?;
    let build = Regex::new(r#"sparkle:version(?:="([^"]+)"|>([^<]+)<)"#).ok()?;
    xml.split("<item")
        .skip(1)
        .filter(|item| !item.contains("<sparkle:channel>"))
        .filter_map(|item| {
            let pick = |re: &Regex| re.captures(item).and_then(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().trim().to_owned()));
            pick(&short).or_else(|| pick(&build))
        })
        .filter(|v| numbers(v).is_some())
        .max_by(|a, b| version_cmp(a, b).unwrap_or(Ordering::Equal))
}

/// macOS and Safari against SOFA: releases missed, their CVEs, how many are exploited (SOFA
/// and CISA KEV) and the highest exploit likelihood (EPSS).
async fn os_section(client: &reqwest::Client, feeds: &Feeds, local: &Local) -> Part {
    let mut part = Part::default();
    let update = Some("open x-apple.systempreferences:com.apple.Software-Update-Settings.extension".to_owned());
    match (&feeds.sofa, local.os.is_empty()) {
        (None, _) => part.skipped.push("macOS patch level: no SOFA feed".into()),
        (_, true) => part.skipped.push("macOS patch level: sw_vers gave no version".into()),
        (Some(sofa), false) => {
            let our_major = major(&local.os);
            let entry = sofa["OSVersions"].as_array().into_iter().flatten().find(|o| major(o["Latest"]["ProductVersion"].as_str().unwrap_or("")) == our_major);
            match entry {
                None => part.skipped.push(format!("macOS patch level: SOFA does not list macOS {}", our_major.unwrap_or(0))),
                Some(entry) => {
                    part.checked.push(format!("macOS patch level ({})", local.os));
                    let latest = entry["Latest"]["ProductVersion"].as_str().unwrap_or("");
                    let missed: Vec<&Value> = entry["SecurityReleases"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|r| r["ProductVersion"].as_str().is_some_and(|v| newer(v, &local.os)))
                        .collect();
                    if !missed.is_empty() {
                        let mut cves = BTreeSet::new();
                        let mut exploited = BTreeSet::new();
                        for release in &missed {
                            for (id, detail) in release["CVEs"].as_object().into_iter().flatten() {
                                cves.insert(id.clone());
                                if detail["ActivelyExploited"] == true || detail["InKEV"] == true {
                                    exploited.insert(id.clone());
                                }
                            }
                            exploited.extend(release["ActivelyExploitedCVEs"].as_array().into_iter().flatten().filter_map(|v| v.as_str().map(str::to_owned)));
                        }
                        let risk = risk_text(client, feeds, &cves, &exploited).await;
                        let text = format!(
                            "macOS {} is {} behind {latest}; {risk}",
                            local.os,
                            plural(missed.len(), "security update", "security updates")
                        );
                        part.add(if exploited.is_empty() { "medium" } else { "high" }, "vuln", text, update.clone(), "SOFA");
                        part.about("OS", "macOS");
                    }
                }
            }
        }
    }
    match (&feeds.safari, local.safari.is_empty()) {
        (None, _) => part.skipped.push("Safari patch level: no SOFA Safari feed".into()),
        (_, true) => part.skipped.push("Safari patch level: Safari's version is unknown".into()),
        (Some(safari), false) => {
            part.checked.push(format!("Safari patch level ({})", local.safari));
            let versions: Vec<&Value> = safari["AppVersions"].as_array().into_iter().flatten().collect();
            let latest = versions.iter().filter_map(|v| v["Latest"]["ProductVersion"].as_str()).max_by(|a, b| version_cmp(a, b).unwrap_or(Ordering::Equal));
            let missed: Vec<&Value> = versions
                .iter()
                .flat_map(|v| v["SecurityReleases"].as_array().into_iter().flatten())
                .filter(|r| r["ProductVersion"].as_str().is_some_and(|v| newer(v, &local.safari)))
                .collect();
            if let Some(latest) = latest.filter(|_| !missed.is_empty()) {
                let mut cves = BTreeSet::new();
                let mut exploited = BTreeSet::new();
                for release in &missed {
                    for (id, detail) in release["CVEs"].as_object().into_iter().flatten() {
                        cves.insert(id.clone());
                        if detail["exploited"] == true {
                            exploited.insert(id.clone());
                        }
                    }
                }
                let risk = risk_text(client, feeds, &cves, &exploited).await;
                let text = format!("Safari {} is behind {latest}; {risk}", local.safari);
                part.add(if exploited.is_empty() { "medium" } else { "high" }, "vuln", text, update, "SOFA");
                part.about("App", "com.apple.Safari");
            }
        }
    }
    part
}

/// "the newer releases fix 392 vulnerabilities, 2 of them actively exploited (CVE-…); the
/// highest exploit likelihood (EPSS) is 26%." KEV adds to the exploited set.
async fn risk_text(client: &reqwest::Client, feeds: &Feeds, cves: &BTreeSet<String>, exploited: &BTreeSet<String>) -> String {
    let mut exploited = exploited.clone();
    exploited.extend(cves.iter().filter(|c| feeds.kev.contains(*c)).cloned());
    let mut text = format!("the newer releases fix {}", plural(cves.len(), "vulnerability", "vulnerabilities"));
    if !exploited.is_empty() {
        let list: Vec<String> = exploited.iter().cloned().collect();
        text.push_str(&format!(", {} actively exploited ({})", plural(list.len(), "of them", "of them"), names(&list, 3)));
    }
    if let Some(score) = epss_max(client, cves).await {
        text.push_str(&format!("; the highest exploit likelihood (EPSS) among them is {:.0}%", score * 100.0));
    }
    text.push('.');
    text
}

/// The highest EPSS score of up to 100 CVEs (one request; nothing when offline).
async fn epss_max(client: &reqwest::Client, cves: &BTreeSet<String>) -> Option<f64> {
    let ids: Vec<&str> = cves.iter().map(String::as_str).filter(|c| c.starts_with("CVE-")).take(100).collect();
    if ids.is_empty() {
        return None;
    }
    let bytes = get(client, &format!("https://api.first.org/data/v1/epss?cve={}", ids.join(","))).await.ok()?;
    let answer: Value = serde_json::from_slice(&bytes).ok()?;
    answer["data"].as_array()?.iter().filter_map(|d| d["epss"].as_str()?.parse::<f64>().ok()).reduce(f64::max)
}

/// Runtimes past their end of life (endoflife.date), and macOS itself.
async fn eol_section(client: &reqwest::Client, local: &Local) -> Part {
    let mut part = Part::default();
    let mut products: BTreeSet<&str> = local.toolchains.iter().map(|t| t.product).collect();
    products.insert("macos");
    let mut cycles: HashMap<&str, Vec<Value>> = HashMap::new();
    for product in products {
        let result = feed(client, &format!("eol-{product}.json"), &format!("https://endoflife.date/api/{product}.json"), json_ok).await;
        if let Some(bytes) = take(&mut part, &format!("end-of-life dates for {product}"), result) {
            cycles.insert(product, serde_json::from_slice(&bytes).unwrap_or_default());
        }
    }
    // The release cycle a version belongs to, in endoflife.date's terms.
    let cycle_of = |product: &str, version: &str| -> Option<String> {
        let n = numbers(version)?;
        let two = n.len() >= 2 && (matches!(product, "python" | "ruby" | "go") || (product == "postgresql" && n[0] < 10));
        Some(if two { format!("{}.{}", n[0], n[1]) } else { n[0].to_string() })
    };
    // Some(date) when the cycle no longer gets fixes ("" when the feed only says true).
    let ended = |product: &str, version: &str| -> Option<String> {
        let cycle = cycle_of(product, version)?;
        let entry = cycles.get(product)?.iter().find(|c| c["cycle"].as_str() == Some(cycle.as_str()))?;
        match &entry["eol"] {
            Value::Bool(true) => Some(String::new()),
            Value::String(date) if days(date).is_some_and(|d| d <= today()) => Some(date.clone()),
            _ => None,
        }
    };
    if !local.os.is_empty() && cycles.contains_key("macos") {
        part.checked.push("macOS end of life".into());
        if let Some(date) = ended("macos", &local.os) {
            part.add(
                "high",
                "outdated",
                format!("macOS {} no longer gets security fixes{}. Upgrade to a newer macOS.", local.os, if date.is_empty() { String::new() } else { format!(" (since {date})") }),
                Some("open x-apple.systempreferences:com.apple.Software-Update-Settings.extension".into()),
                "endoflife.date",
            );
            part.about("OS", "macOS");
        }
    }
    let mut old = Vec::new();
    let mut old_keys: Vec<String> = Vec::new();
    for tool in &local.toolchains {
        if cycles.contains_key(tool.product)
            && let Some(date) = ended(tool.product, &tool.version)
        {
            old.push(format!("{} {} ({}{})", tool.label, tool.version, tool.place, if date.is_empty() { String::new() } else { format!(", ended {date}") }));
            old_keys.push(format!("{}@{}", tool.product, tool.version));
        }
    }
    if !local.toolchains.is_empty() {
        part.checked.push(format!("runtimes ({})", local.toolchains.len()));
    }
    if !old.is_empty() {
        part.add(
            "medium",
            "outdated",
            format!("{} no longer {} security fixes: {}.", plural(old.len(), "runtime", "runtimes"), if old.len() == 1 { "gets" } else { "get" }, names(&old, 6)),
            None,
            "endoflife.date",
        );
        if let [key] = old_keys.as_slice() {
            part.about("Runtime", key.clone());
        }
    }
    part
}

/// Project lockfiles and venvs in OSV, one finding per project. Severity from the advisories;
/// a CVE on CISA's exploited list, or a malicious-package record, makes it high.
async fn deps_section(client: &reqwest::Client, feeds: &Feeds, local: &Local) -> Part {
    let mut part = Part::default();
    let all: Vec<&(&str, String, String)> = local.projects.iter().flat_map(|p| &p.packages).collect::<BTreeSet<_>>().into_iter().collect();
    if all.is_empty() {
        part.skipped.push("project dependencies: no lockfiles found in known projects".into());
        return part;
    }
    let mut vulns: HashMap<&(&str, String, String), Vec<String>> = HashMap::new();
    for chunk in all.chunks(1000) {
        let queries: Vec<Value> = chunk.iter().map(|(eco, name, version)| json!({"package": {"name": name, "ecosystem": eco}, "version": version})).collect();
        let body = serde_json::to_vec(&json!({"queries": queries})).unwrap_or_default();
        let answer = match client.post("https://api.osv.dev/v1/querybatch").header("content-type", "application/json").body(body).send().await {
            Ok(response) if response.status().is_success() => response.bytes().await.ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok()),
            Ok(response) => {
                part.skipped.push(format!("project dependencies: api.osv.dev answered {}", response.status()));
                return part;
            }
            Err(error) => {
                part.skipped.push(format!("project dependencies: api.osv.dev: {error}"));
                return part;
            }
        };
        for (package, result) in chunk.iter().zip(answer.as_ref().and_then(|a| a["results"].as_array()).into_iter().flatten()) {
            let ids: Vec<String> = result["vulns"].as_array().into_iter().flatten().filter_map(|v| v["id"].as_str().map(str::to_owned)).collect();
            if !ids.is_empty() {
                vulns.insert(*package, ids);
            }
        }
    }
    part.checked.push(format!("project dependencies in OSV ({} packages)", all.len()));
    // Details of up to 200 advisories, 20 at a time: severity, CVE aliases, and whether it is
    // only a notice (an unmaintained crate) or withdrawn, which is left out.
    let mut details: HashMap<String, (String, bool)> = HashMap::new();
    let mut notices: HashSet<String> = HashSet::new();
    let wanted: Vec<String> = vulns.values().flatten().cloned().collect::<BTreeSet<_>>().into_iter().take(200).collect();
    for chunk in wanted.chunks(20) {
        let mut tasks = tokio::task::JoinSet::new();
        for id in chunk {
            let (client, id) = (client.clone(), id.clone());
            tasks.spawn(async move {
                let bytes = get(&client, &format!("https://api.osv.dev/v1/vulns/{id}")).await.ok()?;
                Some((id, serde_json::from_slice::<Value>(&bytes).ok()?))
            });
        }
        while let Some(done) = tasks.join_next().await {
            let Ok(Some((id, vuln))) = done else { continue };
            if vuln["withdrawn"].is_string() || matches!(vuln["affected"][0]["database_specific"]["informational"].as_str(), Some("unmaintained" | "notice")) {
                notices.insert(id);
                continue;
            }
            let label = vuln["database_specific"]["severity"].as_str().or_else(|| vuln["affected"][0]["ecosystem_specific"]["severity"].as_str());
            let kev = vuln["aliases"].as_array().into_iter().flatten().filter_map(Value::as_str).any(|a| feeds.kev.contains(a)) || feeds.kev.contains(&id);
            details.insert(id, (label.map(severity_of).unwrap_or("medium").to_owned(), kev));
        }
    }
    for ids in vulns.values_mut() {
        ids.retain(|id| !notices.contains(id));
    }
    vulns.retain(|_, ids| !ids.is_empty());
    let rank = |s: &str| match s {
        "high" => 0,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    };
    for project in &local.projects {
        let hits: Vec<(&(&str, String, String), &Vec<String>)> = project.packages.iter().filter_map(|p| vulns.get_key_value(p).map(|(k, v)| (*k, v))).collect();
        if hits.is_empty() {
            continue;
        }
        let ids: BTreeSet<&String> = hits.iter().flat_map(|(_, ids)| ids.iter()).collect();
        let malicious = ids.iter().any(|id| id.starts_with("MAL-"));
        let exploited = ids.iter().any(|id| details.get(*id).is_some_and(|d| d.1));
        let worst = ids.iter().filter_map(|id| details.get(*id).map(|d| d.0.as_str())).min_by_key(|s| rank(s)).unwrap_or("medium");
        let severity = if malicious || exploited { "high" } else { worst };
        let packages: Vec<String> = hits.iter().map(|((eco, name, version), _)| format!("{name} {version} ({eco})")).collect();
        let id_list: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        let ecosystems: BTreeSet<&str> = hits.iter().map(|((eco, _, _), _)| *eco).collect();
        let shown = tilde(&project.root);
        let fix = match ecosystems.iter().next() {
            Some(&"npm") if ecosystems.len() == 1 => Some(format!("cd {shown} && npm audit fix")),
            Some(&"crates.io") if ecosystems.len() == 1 => Some(format!("cd {shown} && cargo update")),
            _ => None,
        };
        part.add(
            severity,
            "vuln",
            format!(
                "{shown}: {} with {}{}{}: {} ({}).",
                plural(packages.len(), "dependency", "dependencies"),
                plural(id_list.len(), "known vulnerability", "known vulnerabilities"),
                if malicious { ", including a known malicious package" } else { "" },
                if exploited { ", one is being exploited (CISA KEV)" } else { "" },
                names(&packages, 5),
                names(&id_list, 3)
            ),
            fix,
            "osv",
        );
        match hits.as_slice() {
            [((eco, name, _), _)] => part.about("Package", format!("{eco}:{name}")),
            _ => part.about("Repo", project.root.display().to_string()),
        }
    }
    part
}

/// Local Docker images, scanned with grype or osv-scanner when one is installed.
fn docker_checks() -> Part {
    let mut part = Part::default();
    let Some(docker) = which("docker") else {
        part.skipped.push("Docker images: Docker is not installed".into());
        return part;
    };
    let docker = docker.display().to_string();
    match run(&docker, &["info", "--format", "{{.ServerVersion}}"], Duration::from_secs(10)) {
        Ok(out) if out.ok && !out.stdout.trim().is_empty() => {}
        _ => {
            part.skipped.push("Docker images: Docker is not running".into());
            return part;
        }
    }
    let images: Vec<String> = match run(&docker, &["images", "--format", "{{.Repository}}:{{.Tag}}"], STEP) {
        Ok(out) => out.stdout.lines().filter(|l| !l.contains("<none>") && !l.trim().is_empty()).map(str::to_owned).collect(),
        Err(error) => {
            part.skipped.push(format!("Docker images: {error}"));
            return part;
        }
    };
    part.checked.push(format!("Docker images ({})", images.len()));
    let scanner = which("grype").map(|p| ("grype", p)).or_else(|| which("osv-scanner").map(|p| ("osv-scanner", p)));
    let Some((tool, path)) = scanner else {
        if !images.is_empty() {
            part.skipped.push(format!("Docker image scan: neither grype nor osv-scanner is installed (brew install grype), so {} not scanned", plural(images.len(), "image is", "images are")));
        }
        return part;
    };
    let path = path.display().to_string();
    for image in &images {
        let out = match tool {
            "grype" => run(&path, &[image.as_str(), "-o", "json", "-q"], Duration::from_secs(40)),
            _ => run(&path, &["scan", "image", "--format", "json", image.as_str()], Duration::from_secs(40)),
        };
        let report = match out.map(|o| serde_json::from_str::<Value>(&o.stdout)) {
            Ok(Ok(report)) => report,
            Ok(Err(_)) => {
                part.skipped.push(format!("Docker image {image}: unreadable {tool} output"));
                continue;
            }
            Err(error) => {
                part.skipped.push(format!("Docker image {image}: {error}"));
                continue;
            }
        };
        let severities: Vec<String> = if tool == "grype" {
            report["matches"].as_array().into_iter().flatten().filter_map(|m| m["vulnerability"]["severity"].as_str().map(str::to_owned)).collect()
        } else {
            report["results"]
                .as_array()
                .into_iter()
                .flatten()
                .flat_map(|r| r["packages"].as_array().into_iter().flatten())
                .flat_map(|p| p["vulnerabilities"].as_array().into_iter().flatten())
                .map(|v| v["database_specific"]["severity"].as_str().unwrap_or("").to_owned())
                .collect()
        };
        if severities.is_empty() {
            continue;
        }
        let serious = severities.iter().filter(|s| severity_of(s) == "high" && !s.is_empty()).count();
        part.add(
            if serious > 0 { "high" } else { "medium" },
            "vuln",
            format!(
                "The Docker image {image} has {}{}.",
                plural(severities.len(), "known vulnerability", "known vulnerabilities"),
                if serious > 0 { format!(", {serious} critical or high") } else { String::new() }
            ),
            Some(format!("docker pull {image}")),
            tool,
        );
    }
    part
}

/// Browser extensions on the malicious list, and ones that can read every site and also reach
/// cookies, the debugger, the clipboard or programs on the Mac.
fn extension_findings(feeds: &Feeds, local: &Local) -> Part {
    let mut part = Part::default();
    if feeds.malext.is_empty() {
        part.skipped.push("malicious browser extensions: no copy of the MalExt Sentry list".into());
    } else {
        part.checked.push(format!("browser extensions against the malicious list ({} ids)", feeds.malext.len()));
    }
    for ext in local.extensions.iter().filter(|e| feeds.malext.contains(&e.id)) {
        part.add(
            "high",
            "app",
            format!(
                "The {} extension {} ({}) was removed from its store for malware, spyware or policy abuse, but is still installed. Remove it.",
                ext.browser, ext.name, ext.id
            ),
            None,
            "MalExt Sentry",
        );
        part.about("Extension", extension_key(ext));
    }
    let powerful: Vec<String> = local
        .extensions
        .iter()
        .filter(|e| e.all_sites && !e.risky.is_empty())
        .map(|e| format!("{} in {} ({})", e.name, e.browser, e.risky.join(", ")))
        .collect();
    if !powerful.is_empty() {
        part.add(
            "info",
            "app",
            format!(
                "{} can read and change every website and also reach more: {}. Keep only the ones you trust.",
                plural(powerful.len(), "browser extension", "browser extensions"),
                names(&powerful, 6)
            ),
            None,
            "browser extensions",
        );
    }
    part
}

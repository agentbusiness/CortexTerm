//! Persistence: a snapshot of everything that starts by itself (KnockKnock's list: launch items,
//! login items inside apps, cron, periodic and at jobs, emond, shell startup files, SSH's
//! authorized keys, git's hooks path, the npm registry, editor tasks that run on folder open,
//! authorization plugins, startup items), kept in the graph as `(:StartItem {key, what,
//! fingerprint*, target, source: baseline})-[:ON]->(:Machine)`, `-[:STARTS]->(:Binary)` for what it
//! starts; an item that went is retired. The first sweep records it; later sweeps report what was
//! added or changed, and each change goes to the stream `persistence.changes`, kept a month (the
//! incident timeline reads them). Loaded once at start and kept in RAM.
//!
//! The full login-items database (BTM) needs root, so it is never read on a timer: the sweep offers
//! the command and reads its output on the next run (`deep`).

use crate::graph::{self, Props, r};
use crate::sweep::Part;
use crate::util::{home, now_ms, plural, run, tilde};
use crate::{codesign, deep, host, launch, malware};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

const DAY_MS: u64 = 24 * 3600 * 1000;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Item {
    /// What it is, in words ("launch agent com.example.foo").
    pub what: String,
    /// A fingerprint of its content (hash, size and time, or the setting's value).
    pub value: String,
    /// The program it starts, when there is one.
    #[serde(default)]
    pub target: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Change {
    pub at: u64,
    /// added | changed | removed
    pub change: String,
    pub key: String,
    pub severity: String,
    pub text: String,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Baseline {
    pub at: u64,
    pub items: BTreeMap<String, Item>,
    /// The last month of changes, oldest first.
    #[serde(default)]
    pub changes: Vec<Change>,
}

/// The stream of changes.
pub const CHANGES: &str = "persistence.changes";

static BASELINE: Mutex<Option<Baseline>> = Mutex::new(None);

fn lock_baseline() -> std::sync::MutexGuard<'static, Option<Baseline>> {
    BASELINE.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// The baseline and the month of changes, from the graph (at start).
pub async fn load() -> Result<usize, String> {
    let rows = graph::query_all(
        "MATCH (s:StartItem) WHERE s.source = 'baseline' AND (s.state IS NULL OR s.state <> 'gone') RETURN s.key, s.what, s.fingerprint, s.target, s.last_ms ORDER BY s.key",
        json!({}),
    )
    .await?;
    let mut baseline = Baseline::default();
    for row in &rows {
        baseline.at = baseline.at.max(graph::number(&row[4]));
        baseline.items.insert(graph::text(&row[0]), Item { what: graph::text(&row[1]), value: graph::text(&row[2]), target: graph::text(&row[3]) });
    }
    for entry in graph::stream_read(CHANGES, now_ms().saturating_sub(30 * DAY_MS)).await? {
        if let Ok(change) = serde_json::from_value::<Change>(entry.value) {
            baseline.changes.push(change);
        }
    }
    let count = baseline.items.len();
    *lock_baseline() = Some(baseline);
    Ok(count)
}

/// The last month of changes, oldest first (empty before the graph is loaded).
pub fn changes() -> Vec<Change> {
    lock_baseline().as_ref().map(|b| b.changes.clone()).unwrap_or_default()
}

/// An item as its graph unit.
pub fn item_unit(key: &str, item: &Item, machine: &cc_protocol::contracts::memory::GraphRef) -> graph::Unit {
    let mut unit = graph::Unit::default();
    unit.node("StartItem", key).p("what", item.what.clone()).p("target", item.target.clone()).p("source", "baseline").t("fingerprint", item.value.clone());
    unit.edge(r("StartItem", key), "ON", machine.clone());
    if item.target.starts_with('/') {
        unit.node("Binary", item.target.clone());
        unit.edge(r("StartItem", key), "STARTS", r("Binary", item.target.clone()));
    }
    unit
}

/// The key a launch item's plist has (what a persistence alert is about).
pub fn launch_key(plist: &Path) -> String {
    format!("launch:{}", plist.display())
}

/// Whether the baseline holds an item (so the graph has its node).
pub fn known(key: &str) -> bool {
    lock_baseline().as_ref().is_some_and(|b| b.items.contains_key(key))
}

pub fn checks(discovery: crate::filesystem::Shared) -> Part {
    let mut part = Part::default();
    if !cfg!(target_os = "macos") {
        part.skipped.push("persistence baseline: not a Mac".into());
        return part;
    }
    let now = now_ms();
    let found = discovery.get();
    if discovery.is_cancelled() {
        part.skipped.push("filesystem checks: cancelled before completion".into());
        return part;
    }
    let discovery = found;
    discovery.report(&mut part);
    let items = snapshot(&mut part, discovery);
    let mut slot = lock_baseline();
    let keeps = slot.is_some() && graph::machine().is_some();
    let mut scratch = Baseline::default();
    let baseline: &mut Baseline = match slot.as_mut() {
        Some(baseline) => baseline,
        None => &mut scratch,
    };
    let before = baseline.changes.len();
    if baseline.at == 0 {
        part.add(
            "info",
            "persistence",
            if keeps {
                format!("Recorded what starts by itself on this Mac ({}); later sweeps report what changes.", plural(items.len(), "item", "items"))
            } else {
                format!("{} start by themselves on this Mac; once memory answers they are recorded, and later checks report what changes.", plural(items.len(), "item", "items"))
            },
            None,
            "persistence",
        );
    } else {
        for (key, item) in &items {
            let change = match baseline.items.get(key) {
                None => "added",
                Some(old) if old.value != item.value || old.target != item.target => "changed",
                _ => continue,
            };
            let (severity, why) = judge(item);
            let verb = if change == "added" { "New" } else { "Changed" };
            let starts = if item.target.is_empty() { String::new() } else { format!(", which starts {}", tilde(Path::new(&item.target))) };
            baseline.changes.push(Change {
                at: now,
                change: change.into(),
                key: key.clone(),
                severity: severity.into(),
                text: format!("{verb} since the last sweep: {}{starts}{why}.", item.what),
            });
        }
        for (key, item) in &baseline.items {
            if !items.contains_key(key) {
                baseline.changes.push(Change {
                    at: now,
                    change: "removed".into(),
                    key: key.clone(),
                    severity: "info".into(),
                    text: format!("Removed since the last sweep: {}.", item.what),
                });
            }
        }
    }
    let fresh: Vec<serde_json::Value> = baseline.changes[before..].iter().filter_map(|c| serde_json::to_value(c).ok()).collect();
    baseline.changes.retain(|c| now.saturating_sub(c.at) < 30 * DAY_MS);
    // A day of changes stays in the report, so a second sweep the same day still shows them.
    for change in baseline.changes.iter().filter(|c| now.saturating_sub(c.at) < DAY_MS && c.change != "removed") {
        part.add(&change.severity, "persistence", change.text.clone(), None, "persistence baseline");
        if items.contains_key(&change.key) {
            part.about("StartItem", change.key.clone());
        }
    }
    if keeps && let Some(machine) = graph::machine() {
        // Every item goes with the sweep (its findings point at them); what went is retired.
        for (key, item) in items.iter().filter(|(key, _)| key.len() <= 1000) {
            part.graph.units.push(item_unit(key, item, &machine));
        }
        let gone: Vec<_> = baseline.items.keys().filter(|k| !items.contains_key(*k)).map(|k| r("StartItem", k.clone())).collect();
        if !gone.is_empty() {
            graph::retire(gone, "removed");
        }
        if !fresh.is_empty() {
            graph::append(CHANGES, fresh, 30);
        }
        baseline.at = now;
        baseline.items = items;
    }
    drop(slot);
    btm(&mut part);
    part
}

/// medium, or high (with why) when what it starts is unsigned, quarantined, hidden or temporary.
fn judge(item: &Item) -> (&'static str, String) {
    if item.target.is_empty() {
        return ("medium", String::new());
    }
    let target = Path::new(&item.target);
    let text = item.target.as_str();
    if ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/Users/Shared/"].iter().any(|p| text.starts_with(p)) {
        return ("high", " from a temporary or shared folder".into());
    }
    if target.components().any(|c| c.as_os_str().to_string_lossy().starts_with('.')) {
        return ("high", " from a hidden folder".into());
    }
    if !target.exists() {
        return ("medium", " (the program does not exist)".into());
    }
    if host::quarantined(target) {
        return ("high", " (still quarantined: downloaded and never approved)".into());
    }
    let sig = codesign::check(target);
    if sig.unsigned() {
        return ("high", format!(" (the program is {})", if sig.status == "adhoc" { "only ad-hoc signed" } else { "not signed" }));
    }
    ("medium", String::new())
}

/// A fingerprint of a file: its SHA-256, or its size and time for a folder or an unreadable file.
fn fingerprint(path: &Path) -> String {
    if path.is_file()
        && let Some(hash) = malware::sha256(path)
    {
        return hash;
    }
    std::fs::metadata(path)
        .map(|m| format!("{}:{}", m.len(), m.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_secs()).unwrap_or(0)))
        .unwrap_or_default()
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut list: Vec<PathBuf> = std::fs::read_dir(dir).into_iter().flatten().flatten().map(|e| e.path()).collect();
    list.sort();
    list
}

fn snapshot(part: &mut Part, discovery: &crate::filesystem::Discovery) -> BTreeMap<String, Item> {
    let mut items = BTreeMap::new();
    let file = |items: &mut BTreeMap<String, Item>, kind: &str, path: &Path, target: String| {
        if std::fs::symlink_metadata(path).is_ok() {
            items.insert(format!("{kind}:{}", path.display()), Item { what: format!("{kind} {}", tilde(path)), value: fingerprint(path), target });
        }
    };

    for item in launch::all() {
        items.insert(
            format!("launch:{}", item.plist.display()),
            Item { what: format!("{} {} ({})", item.what(), item.label, tilde(&item.plist)), value: fingerprint(&item.plist), target: item.program },
        );
    }

    // Login items and helpers inside apps.
    for app in &discovery.apps {
        for sub in ["Contents/Library/LoginItems", "Contents/Library/LaunchServices"] {
            for inner in entries(&app.join(sub)) {
                let target = if inner.extension().is_some_and(|e| e == "app") || inner.is_file() { inner.display().to_string() } else { String::new() };
                file(&mut items, "login item inside an app", &inner, target);
            }
        }
    }

    match run("/usr/bin/crontab", &["-l"], Duration::from_secs(10)) {
        Ok(out) => {
            let lines: Vec<&str> = out.stdout.lines().filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')).collect();
            for line in lines {
                items.insert(format!("cron:{line}"), Item { what: format!("cron job \"{}\"", crate::util::shorten(line, 120)), value: String::new(), target: String::new() });
            }
        }
        Err(error) => part.skipped.push(format!("cron jobs: {error}")),
    }
    for dir in ["/etc/periodic/daily", "/etc/periodic/weekly", "/etc/periodic/monthly", "/usr/local/etc/periodic/daily", "/usr/local/etc/periodic/weekly", "/usr/local/etc/periodic/monthly"] {
        for path in entries(Path::new(dir)) {
            file(&mut items, "periodic script", &path, path.display().to_string());
        }
    }
    match std::fs::read_dir("/usr/lib/cron/jobs") {
        Ok(read) => {
            for path in read.flatten().map(|e| e.path()) {
                file(&mut items, "at job", &path, String::new());
            }
        }
        Err(_) => part.skipped.push("at jobs: /usr/lib/cron/jobs can only be read by root".into()),
    }
    for dir in ["/etc/emond.d/rules", "/private/var/db/emondClients"] {
        for path in entries(Path::new(dir)) {
            file(&mut items, "emond rule", &path, String::new());
        }
    }
    for name in [".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".bash_profile", ".bashrc", ".profile"] {
        file(&mut items, "shell startup file", &home().join(name), String::new());
    }
    for path in ["/etc/zshrc", "/etc/zprofile", "/etc/zshenv", "/etc/profile", "/etc/bashrc"] {
        file(&mut items, "shell startup file", Path::new(path), String::new());
    }
    for path in entries(Path::new("/etc/paths.d")) {
        file(&mut items, "PATH entry", &path, String::new());
    }
    file(&mut items, "SSH authorized keys file", &home().join(".ssh/authorized_keys"), String::new());
    file(&mut items, "SSH login script", &home().join(".ssh/rc"), String::new());

    if let Ok(out) = run("git", &["config", "--global", "--get", "core.hooksPath"], Duration::from_secs(5)) {
        let hooks = out.stdout.trim();
        if !hooks.is_empty() {
            items.insert("git:core.hooksPath".into(), Item { what: format!("global git hooks folder {hooks}"), value: hooks.into(), target: String::new() });
        }
    }
    // Only the registry lines: an .npmrc also holds tokens, which are never stored.
    if let Ok(text) = std::fs::read_to_string(home().join(".npmrc")) {
        let registries: Vec<&str> = text.lines().map(str::trim).filter(|l| l.starts_with("registry") || (l.starts_with('@') && l.contains(":registry"))).collect();
        if !registries.is_empty() {
            items.insert("npm:registry".into(), Item { what: format!("npm registry setting ({})", registries.join(", ")), value: registries.join("\n"), target: String::new() });
        }
    }
    for repo in &discovery.projects {
        for editor in [".vscode", ".cursor"] {
            let tasks = repo.join(editor).join("tasks.json");
            if std::fs::read_to_string(&tasks).is_ok_and(|t| t.contains("folderOpen")) {
                file(&mut items, "editor task that runs when the folder opens", &tasks, String::new());
            }
        }
    }
    for path in entries(Path::new("/Library/Security/SecurityAgentPlugins")) {
        file(&mut items, "authorization plugin", &path, path.display().to_string());
    }
    for path in entries(Path::new("/Library/StartupItems")) {
        file(&mut items, "startup item", &path, String::new());
    }
    part.checked.push(format!("persistence baseline ({})", plural(items.len(), "item", "items")));
    items
}

// --- 39. The full login-items database, read from a dump the person makes.

fn btm(part: &mut Part) {
    let file = deep::dir().join("btm.txt");
    let command = format!("mkdir -p {dir} && sudo sfltool dumpbtm > {file}", dir = malware::quote(&deep::dir()), file = malware::quote(&file));
    let dump = deep::btm();
    let fresh = dump.as_ref().map(|(at, _)| now_ms().saturating_sub(*at) < 7 * DAY_MS);
    match fresh {
        None => {
            part.add(
                "info",
                "persistence",
                "macOS keeps a full list of login and background items that needs an administrator to read. Run the command once in a terminal and the next sweep checks it.".into(),
                Some(command),
                "btm",
            );
            return;
        }
        Some(false) => {
            part.add("info", "persistence", "The saved login-items list is more than a week old; run the command again for a fresh one.".into(), Some(command), "btm");
            return;
        }
        Some(true) => {}
    }
    let records: Vec<BTreeMap<String, String>> = dump.map(|(_, records)| records).unwrap_or_default();
    part.checked.push(format!("login-items database (BTM, {})", plural(records.len(), "item", "items")));
    if records.len() < 5 {
        part.add(
            "medium",
            "persistence",
            format!("The login-items database lists only {}; an emptied database can mean someone reset it to hide an item.", plural(records.len(), "item", "items")),
            None,
            "btm",
        );
    }
    let mut flagged = 0;
    for record in &records {
        let get = |key: &str| record.get(key).map(String::as_str).filter(|v| !v.is_empty() && *v != "(null)").unwrap_or("");
        let disposition = get("Disposition");
        if !disposition.contains("enabled") {
            continue;
        }
        let name = if get("Name").is_empty() { get("Identifier") } else { get("Name") };
        let program = get("Executable Path");
        let program = if program.is_empty() { get("URL").trim_start_matches("file://") } else { program };
        let hidden_or_temp = ["/tmp/", "/private/tmp/", "/Users/Shared/", "/private/var/tmp/"].iter().any(|p| program.starts_with(p)) || program.contains("/.");
        let no_developer = get("Team Identifier").is_empty() && get("Developer Name").is_empty();
        let unsigned = no_developer && program.starts_with('/') && Path::new(program).exists() && codesign::check(Path::new(program)).unsigned();
        let (severity, why) = if hidden_or_temp {
            ("high", "runs from a hidden, temporary or shared folder")
        } else if unsigned {
            ("medium", "has no developer and its program is not signed")
        } else {
            continue;
        };
        flagged += 1;
        if flagged > 20 {
            break;
        }
        let kind = get("Type").split(" (").next().unwrap_or("");
        part.add(severity, "persistence", format!("The login item {name} ({kind}) {why}: {program}."), None, "btm");
    }
}

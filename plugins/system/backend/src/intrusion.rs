//! Intrusion evidence: a digest of the unified log (fixed queries, each time-limited: XProtect,
//! Gatekeeper, privacy grants, sudo, SSH and screen-sharing logins, new background items) and the
//! incident timeline. Deep collection is the native protection sensor's.

use crate::procs::Snapshot;
use crate::sweep::Part;
use crate::util::{now_ms, plural, run, shorten, tilde};
use crate::{codesign, launch, malware, persist};
use cc_protocol::contracts::system::{MonitorReport, Timeline, TimelineParams, TimelineRow};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::time::Duration;

const DAY_MS: u64 = 24 * 3600 * 1000;

/// One fixed query: what it looks for and its predicate. Each returns in a few seconds on a busy
/// Mac; syspolicyd's own Gatekeeper lines took 20 s and more, so only the dialog agent is read.
const QUERIES: [(&str, &str); 7] = [
    ("xprotect", r#"(subsystem == "com.apple.xprotect" OR subsystem BEGINSWITH "com.apple.XProtect") AND (eventMessage CONTAINS[c] "detect" OR eventMessage CONTAINS[c] "remediat" OR eventMessage CONTAINS[c] "malware")"#),
    ("gatekeeper", r#"process == "CoreServicesUIAgent" AND eventMessage CONTAINS[c] "rejection""#),
    ("privacy", r#"subsystem == "com.apple.TCC" AND (eventMessage CONTAINS "Update Access Record" OR eventMessage CONTAINS "publishAccessChangedEvent")"#),
    ("sudo", r#"process == "sudo" AND eventMessage CONTAINS "pam_sm_authenticate""#),
    ("ssh", r#"process == "sshd" AND (eventMessage CONTAINS "Accepted" OR eventMessage CONTAINS "Failed password" OR eventMessage CONTAINS "Invalid user")"#),
    ("screen sharing", r#"process == "screensharingd" AND eventMessage CONTAINS[c] "authentication""#),
    ("background items", r#"subsystem == "com.apple.backgroundtaskmanagement" AND eventMessage CONTAINS "registerLaunchItem" AND NOT eventMessage CONTAINS "found existing""#),
];

/// One log line a query returned.
pub struct LogRow {
    pub at: u64,
    pub query: &'static str,
    pub pid: u32,
    pub process: String,
    pub message: String,
}

/// `2026-10-29 17:50:47.123456+0100` -> Unix ms.
fn parse_time(text: &str) -> Option<u64> {
    let (date, rest) = text.split_once(' ')?;
    let mut d = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, day) = (d.next()??, d.next()??, d.next()??);
    let split = rest.rfind(['+', '-'])?;
    let (clock, zone) = rest.split_at(split);
    let mut t = clock.split(':');
    let (hh, mm) = (t.next()?.parse::<i64>().ok()?, t.next()?.parse::<i64>().ok()?);
    let secs: f64 = t.next()?.parse().ok()?;
    let sign = if zone.starts_with('-') { -1 } else { 1 };
    let zone = zone[1..].replace(':', "");
    let offset = sign * (zone.get(0..2)?.parse::<i64>().ok()? * 3600 + zone.get(2..4).unwrap_or("0").parse::<i64>().unwrap_or(0) * 60);
    // Days from the civil date (Howard Hinnant's algorithm).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let ms = (days * 86_400 + hh * 3600 + mm * 60 - offset) * 1000 + (secs * 1000.0) as i64;
    u64::try_from(ms).ok()
}

/// Run the fixed queries over the last `minutes`. Returns the rows, what ran and what did not.
pub fn log_rows(minutes: u64) -> (Vec<LogRow>, Vec<String>, Vec<String>) {
    let (mut rows, mut ran, mut failed) = (Vec::new(), Vec::new(), Vec::new());
    let last = format!("{}m", minutes.max(1));
    for (query, predicate) in QUERIES {
        let out = match run("/usr/bin/log", &["show", "--style", "ndjson", "--last", &last, "--predicate", predicate], Duration::from_secs(30)) {
            Ok(out) => out,
            Err(error) => {
                failed.push(format!("system log ({query}): {error}"));
                continue;
            }
        };
        ran.push(query);
        for line in out.stdout.lines() {
            let Ok(event) = serde_json::from_str::<Value>(line) else { continue };
            let message = event["eventMessage"].as_str().unwrap_or("").trim();
            if message.is_empty() {
                continue;
            }
            rows.push(LogRow {
                at: event["timestamp"].as_str().and_then(parse_time).unwrap_or(0),
                query,
                pid: event["processID"].as_u64().unwrap_or(0) as u32,
                process: event["processImagePath"].as_str().unwrap_or("").rsplit('/').next().unwrap_or("").to_owned(),
                message: message.to_owned(),
            });
        }
    }
    let checked = if ran.is_empty() { Vec::new() } else { vec![format!("system log of the last 24 hours ({})", ran.join(", "))] };
    (rows, checked, failed)
}

/// Whether a row is evidence worth showing (the queries also return routine lines).
fn notable(row: &LogRow) -> bool {
    match row.query {
        "xprotect" => {
            (row.message.contains("Status:") && !row.message.contains("NoThreatDetected"))
                || (row.message.to_ascii_lowercase().contains("malware") && !row.message.contains("Forwarding detection"))
        }
        "sudo" => false,
        _ => true,
    }
}

fn clock(at: u64) -> String {
    let secs = (at / 1000) as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: localtime_r writes only into `tm`.
    unsafe { libc::localtime_r(&secs, &mut tm) };
    format!("{:02}-{:02} {:02}:{:02}", tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
}

pub fn checks() -> Part {
    let mut part = Part::default();
    if !cfg!(target_os = "macos") {
        part.skipped.push("system log digest: not a Mac".into());
        return part;
    }
    let (rows, checked, failed) = log_rows(24 * 60);
    part.checked.extend(checked);
    part.skipped.extend(failed);
    digest(&mut part, &rows);
    part
}

fn digest(part: &mut Part, rows: &[LogRow]) {
    let mut seen = BTreeSet::new();
    for row in rows.iter().filter(|r| notable(r)) {
        let message = shorten(&row.message.replace('\n', " "), 200);
        if !seen.insert((row.query, message.clone())) {
            continue;
        }
        let (severity, text) = match row.query {
            "xprotect" => ("high", format!("XProtect reported at {}: {message}", clock(row.at))),
            "gatekeeper" => ("medium", format!("Gatekeeper blocked a program at {}: {message}", clock(row.at))),
            "privacy" => ("info", format!("A privacy permission changed at {}: {message}", clock(row.at))),
            "ssh" if row.message.contains("Accepted") => ("medium", format!("Someone logged in over SSH at {}: {message}", clock(row.at))),
            "ssh" => continue,
            "screen sharing" => ("medium", format!("Screen sharing authentication at {}: {message}", clock(row.at))),
            "background items" => {
                let (severity, by) = background_item(&row.message);
                (severity, format!("A new background item was registered at {}{by}: {message}", clock(row.at)))
            }
            _ => continue,
        };
        if seen.len() > 40 {
            break;
        }
        part.add(severity, "intrusion", text, None, "system log");
    }
    let failed_ssh = rows.iter().filter(|r| r.query == "ssh" && !r.message.contains("Accepted")).count();
    if failed_ssh > 0 {
        let severity = if failed_ssh >= 20 { "medium" } else { "info" };
        part.add(severity, "intrusion", format!("{} over SSH in the last 24 hours.", plural(failed_ssh, "failed login", "failed logins")), None, "system log");
    }
    // One sudo process authenticates once; a wrong password says "incorrect". A typo, or Touch ID
    // falling back to the password, makes a wrong one now and then; guessing makes many, over
    // several tries of sudo.
    let sudo: BTreeSet<u32> = rows.iter().filter(|r| r.query == "sudo").map(|r| r.pid).collect();
    let wrong = rows.iter().filter(|r| r.query == "sudo" && r.message.contains("incorrect")).count();
    let wrong_tries: BTreeSet<u32> = rows.iter().filter(|r| r.query == "sudo" && r.message.contains("incorrect")).map(|r| r.pid).collect();
    if !sudo.is_empty() {
        let severity = if wrong >= 6 && wrong_tries.len() >= 3 { "medium" } else { "info" };
        let mut text = format!("sudo asked for the password {} in the last 24 hours", plural(sudo.len(), "time", "times"));
        if wrong > 0 {
            text.push_str(&format!(", {} wrong", plural(wrong, "password was", "passwords were")));
        }
        part.add(severity, "intrusion", format!("{text}."), None, "system log");
    }
}

/// How much a background item registration matters, and who made the program: info when Apple
/// or a notarized developer's app registers it (an app installing or updating its own helper),
/// else medium.
fn background_item(message: &str) -> (&'static str, String) {
    // `url=Contents/Library/LaunchAgents/x.plist -- file:///Applications/X.app/` or a full URL.
    let urls: Vec<&str> = message.split(|c: char| c.is_whitespace() || c == ',').filter_map(|w| w.trim_start_matches("url=").strip_prefix("file://")).collect();
    let Some(base) = urls.first() else { return ("medium", String::new()) };
    let decode = |text: &str| text.replace("%20", " ").replace("%28", "(").replace("%29", ")");
    let mut path = std::path::PathBuf::from(decode(base));
    if path.extension().is_some_and(|e| e == "plist")
        && let Some(item) = launch::inspect(&path).filter(|i| i.program.starts_with('/'))
    {
        path = std::path::PathBuf::from(item.program);
    }
    if !path.exists() {
        return ("medium", String::new());
    }
    let sig = codesign::check(&path);
    if sig.apple {
        return ("info", " by Apple's own software".into());
    }
    if codesign::notarized(&path) == Some(true) {
        return ("info", format!(" by {}, notarized by Apple", sig.signer()));
    }
    ("medium", format!(" by {} ({})", tilde(&path), if sig.unsigned() { "not properly signed" } else { "not notarized" }))
}

// --- 46. The incident timeline.

/// Time-ordered rows about a process or a file: process starts, persistence changes, the system
/// log's notable lines, downloads, and the monitor log when one runs. Code gathers; the model
/// marks and explains. Blocking (runs `log show`).
pub fn timeline(params: &TimelineParams, snapshot: &Snapshot, monitor: Option<&MonitorReport>) -> Timeline {
    let now = now_ms();
    let since = if params.since_ms == 0 { now.saturating_sub(DAY_MS) } else { params.since_ms };
    let path = params.path.as_deref().filter(|p| !p.is_empty());
    let matches = |text: &str| path.is_none_or(|p| text.contains(p) || Path::new(p).file_name().is_some_and(|n| text.contains(&*n.to_string_lossy())));
    let mut timeline = Timeline::default();
    let mut add = |at: u64, source: &str, text: String| {
        if at >= since {
            timeline.rows.push(TimelineRow { at, source: source.into(), text });
        }
    };

    if let Some(pid) = params.pid {
        let mut kids: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        for entry in &snapshot.entries {
            kids.entry(entry.proc.ppid).or_default().push(entry.proc.pid);
        }
        let mut family = vec![pid];
        let mut at = 0;
        while at < family.len() && family.len() < 64 {
            family.extend(kids.get(&family[at]).cloned().unwrap_or_default());
            at += 1;
        }
        for entry in snapshot.entries.iter().filter(|e| family.contains(&e.proc.pid)) {
            let sig = codesign::check(Path::new(&entry.exe));
            add(
                entry.proc.started,
                "process",
                format!("{} (pid {}, parent {}) started: {} [{}]", entry.proc.name, entry.proc.pid, entry.proc.ppid, shorten(&entry.proc.command, 200), sig.status),
            );
        }
    }
    if let Some(path) = path {
        let file = Path::new(path);
        if let Ok(meta) = std::fs::metadata(file) {
            let ms = |t: std::io::Result<std::time::SystemTime>| t.ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map(|d| d.as_millis() as u64).unwrap_or(0);
            add(ms(meta.created()), "file", format!("{} was created", tilde(file)));
            add(ms(meta.modified()), "file", format!("{} was last changed", tilde(file)));
        }
        if let Some(url) = malware::where_from(file) {
            timeline.notes.push(format!("{} says it was downloaded from {url}.", tilde(file)));
        }
        if let Some(sha) = malware::sha256(file).filter(|_| file.is_file()) {
            timeline.notes.push(format!("{} has SHA-256 {sha}.", tilde(file)));
        }
    }
    for change in persist::changes().iter().filter(|c| matches(&c.text)) {
        add(change.at, "persistence", change.text.clone());
    }
    match malware::downloads(since) {
        Ok(list) => {
            for d in list.iter().filter(|d| matches(&d.url) || matches(&d.origin)) {
                let agent = if d.agent.is_empty() { String::new() } else { format!(" with {}", d.agent) };
                let what = [&d.url, &d.origin].into_iter().find(|u| !u.is_empty()).map(|u| u.as_str()).unwrap_or("a file");
                add(d.at, "download", format!("Downloaded {what}{agent}"));
            }
        }
        Err(error) => timeline.skipped.push(format!("download history: {error}")),
    }
    let minutes = now.saturating_sub(since) / 60_000 + 1;
    let (rows, _, failed) = log_rows(minutes.min(7 * 24 * 60));
    for row in rows.iter().filter(|r| notable(r) || r.query == "sudo" && r.message.contains("incorrect")) {
        let wanted = match (params.pid, path) {
            (None, None) => true,
            (pid, _) => pid == Some(row.pid) || path.is_some() && matches(&row.message),
        };
        if wanted {
            add(row.at, "log", format!("{} ({}): {}", row.query, row.process, shorten(&row.message.replace('\n', " "), 240)));
        }
    }
    timeline.skipped.extend(failed);
    if let Some(report) = monitor {
        for event in &report.events {
            if event.change == "open" && matches(&event.file.name) {
                add(event.at, "monitor", format!("pid {} opened {} {}", event.pid, event.file.kind, event.file.name));
            }
        }
        for flag in &report.flags {
            timeline.notes.push(format!("Monitor mode flagged: {flag}"));
        }
    }
    timeline.rows.sort_by_key(|r| r.at);
    if timeline.rows.len() > 400 {
        let excess = timeline.rows.len() - 400;
        timeline.rows.drain(..excess);
    }
    timeline
}

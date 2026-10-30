//! Intrusion evidence: a digest of the unified log (fixed queries, each time-limited: XProtect,
//! Gatekeeper, privacy grants, sudo, SSH and screen-sharing logins, new background items), the
//! optional deep watch with Apple's `eslogger` (root, so only offered as a command; its output is
//! read by the next sweep), and the incident timeline that puts what code can gather in time order.

use crate::procs::Snapshot;
use crate::sweep::Part;
use crate::util::{now_ms, plural, run, shorten, tilde};
use crate::{codesign, deep, malware, persist};
use cc_protocol::contracts::system::{MonitorReport, Timeline, TimelineParams, TimelineRow};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::io::BufRead;
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
    eslogger(&mut part);
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
            "background items" => ("medium", format!("A new background item was registered at {}: {message}", clock(row.at))),
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
    // One sudo process authenticates once; a wrong password says "incorrect".
    let sudo: BTreeSet<u32> = rows.iter().filter(|r| r.query == "sudo").map(|r| r.pid).collect();
    let wrong = rows.iter().filter(|r| r.query == "sudo" && r.message.contains("incorrect")).count();
    if !sudo.is_empty() {
        let severity = if wrong >= 3 { "medium" } else { "info" };
        let mut text = format!("sudo asked for the password {} in the last 24 hours", plural(sudo.len(), "time", "times"));
        if wrong > 0 {
            text.push_str(&format!(", {} wrong", plural(wrong, "password was", "passwords were")));
        }
        part.add(severity, "intrusion", format!("{text}."), None, "system log");
    }
}

// --- 45. The deep watch with eslogger.

const ES_EVENTS: &str = "exec btm_launch_item_add xp_malware_detected xp_malware_remediated tcc_modify gatekeeper_user_override openssh_login screensharing_attach od_create_user";

fn eslogger(part: &mut Part) {
    let file = deep::dir().join("eslogger.jsonl");
    // eslogger needs root and stops with the shell; the background job ends itself after an hour.
    let command = format!(
        "mkdir -p {dir} && sudo sh -c 'eslogger {ES_EVENTS} > \"{out}\" & pid=$!; sleep 3600; kill $pid'",
        dir = malware::quote(&deep::dir()),
        out = file.display()
    );
    let recording = deep::eslogger(flag_events);
    let Some((at, events, notes)) = recording.filter(|(at, _, _)| now_ms().saturating_sub(*at) < 7 * DAY_MS) else {
        part.add(
            "info",
            "intrusion",
            "For a closer look, Apple's eslogger can record every program start, new background item, XProtect detection and permission change for an hour. It needs an administrator; run the command in a terminal (it needs Full Disk Access for that terminal) and the next sweep reads what it saw.".into(),
            Some(command),
            "eslogger",
        );
        return;
    };
    for (severity, text) in notes {
        part.add(&severity, "intrusion", text, None, "eslogger");
    }
    part.checked.push(format!("eslogger recording of {} ago ({})", crate::util::duration_text(now_ms().saturating_sub(at)), plural(events as usize, "event", "events")));
}

/// What an eslogger recording shows: how many events, and the notable ones (severity, text), at
/// most 30.
fn flag_events(file: &Path) -> (usize, Vec<(String, String)>) {
    let Ok(handle) = std::fs::File::open(file) else { return (0, Vec::new()) };
    let mut out = Vec::new();
    // Each odd program is reported once, however often it ran.
    let mut execs: BTreeMap<String, usize> = BTreeMap::new();
    let mut flagged = 0;
    let mut lines = 0;
    for line in std::io::BufReader::new(handle).lines().map_while(Result::ok).take(2_000_000) {
        lines += 1;
        let Ok(record) = serde_json::from_str::<Value>(&line) else { continue };
        let event = &record["event"];
        let at = record["time"].as_str().unwrap_or("");
        let note = if let Some(exec) = event.get("exec") {
            let target = &exec["target"];
            let path = target["executable"]["path"].as_str().unwrap_or("");
            let platform = target["is_platform_binary"].as_bool().unwrap_or(false);
            let unsigned = target["team_id"].is_null() && target["signing_id"].is_null();
            let odd = ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/Users/Shared/"].iter().any(|p| path.starts_with(p)) || path.contains("/.");
            let count = execs.entry(path.to_owned()).or_default();
            *count += 1;
            match (!platform && odd && *count == 1, unsigned) {
                (false, _) => None,
                (true, true) => Some(("high", format!("An unsigned program ran from {path}"))),
                (true, false) => Some(("medium", format!("A program ran from {path}"))),
            }
        } else if let Some(add) = event.get("btm_launch_item_add") {
            let item = add["item"]["item_url"].as_str().or_else(|| add["executable_path"].as_str()).unwrap_or("an item");
            Some(("medium", format!("A background item was added: {item}")))
        } else if let Some(hit) = event.get("xp_malware_detected").or_else(|| event.get("xp_malware_remediated")) {
            let what = hit["malware_identifier"].as_str().unwrap_or("malware");
            let path = hit["detected_path"].as_str().unwrap_or("");
            Some(("high", format!("XProtect found {what} in {path}")))
        } else if let Some(tcc) = event.get("tcc_modify") {
            let by = record["process"]["executable"]["path"].as_str().unwrap_or("");
            let platform = record["process"]["is_platform_binary"].as_bool().unwrap_or(false);
            let service = tcc["service"].as_str().unwrap_or("a permission");
            let who = tcc["identity"].as_str().unwrap_or("a program");
            (!platform).then(|| ("medium", format!("{by} changed the {service} permission of {who}")))
        } else if let Some(over) = event.get("gatekeeper_user_override") {
            let path = over["file"]["path"].as_str().or_else(|| over["file_path"].as_str()).unwrap_or("a file");
            Some(("medium", format!("Gatekeeper was overridden for {path}")))
        } else if let Some(login) = event.get("openssh_login") {
            let ok = login["success"].as_bool().unwrap_or(false);
            ok.then(|| ("medium", format!("SSH login as {} from {}", login["username"].as_str().unwrap_or("?"), login["source_address"].as_str().unwrap_or("?"))))
        } else if event.get("screensharing_attach").is_some() {
            Some(("medium", "A screen-sharing session attached".to_owned()))
        } else if let Some(user) = event.get("od_create_user") {
            Some(("high", format!("A user account was created: {}", user["user_name"].as_str().unwrap_or("?"))))
        } else {
            None
        };
        if let Some((severity, text)) = note
            && flagged < 30
        {
            flagged += 1;
            out.push((severity.to_owned(), format!("{text} ({}).", at.get(..19).unwrap_or(at).replace('T', " "))));
        }
    }
    (lines, out)
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

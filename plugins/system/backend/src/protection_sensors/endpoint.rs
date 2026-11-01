//! User-authorized native Endpoint Security capture. The privileged helper has one job: emit
//! allow-listed metadata. This unprivileged reader removes all unrecognized fields before the
//! events reach the collector (in this process) and the `protection.events` stream.

use super::input;
use cc_protocol::contracts::system::{ProtectionSensor, SecurityObservation};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::io::{BufRead, BufReader};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

const MAX_LINE: usize = 64 * 1024;
/// Cleaned events waiting for the collector; more are counted as lost.
const MAX_WAITING: usize = 4096;
/// A sensor without a valid record for this long is stale.
const FRESH_MS: u64 = 120_000;
/// The history of cleaned endpoint events.
const TOPIC: &str = "protection.events";

fn shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

/// The installed sensor service (a LaunchDaemon) and the socket it serves the connecting user on.
const SERVICE: &str = "/Library/LaunchDaemons/ai.cortexterm.event-sensor.plist";
const SOCKET: &str = "/var/run/ai.cortexterm.event-sensor.sock";
static SERVICE_RUNNING: AtomicBool = AtomicBool::new(false);
static SERVICE_STOP: AtomicBool = AtomicBool::new(false);
static SERVICE_PROBLEM: Mutex<Option<String>> = Mutex::new(None);

/// What the service thread handed over and the collector has not taken yet.
struct Feed {
    events: VecDeque<SecurityObservation>,
    /// The last valid native record (0: none yet).
    last_at: u64,
    /// Records lost here (malformed, stale, over the queue) and the most the producer reported.
    lost: u64,
    native_lost: u64,
    stopped: bool,
}

static FEED: Mutex<Feed> = Mutex::new(Feed { events: VecDeque::new(), last_at: 0, lost: 0, native_lost: 0, stopped: false });

fn feed() -> std::sync::MutexGuard<'static, Feed> {
    FEED.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

pub fn service_installed() -> bool {
    Path::new(SERVICE).exists()
}

/// Why the sensor service gives no events, when it said.
pub fn service_problem() -> Option<String> {
    SERVICE_PROBLEM.lock().ok()?.clone()
}

/// While deep monitoring is on, read the installed sensor service's events: no terminal, no
/// sudo. The socket must belong to root and be served by a root process.
pub fn service_capture(on: bool) {
    if !on {
        if SERVICE_RUNNING.load(Ordering::Relaxed) {
            SERVICE_STOP.store(true, Ordering::Relaxed);
        }
        *feed() = Feed { events: VecDeque::new(), last_at: 0, lost: 0, native_lost: 0, stopped: false };
        return;
    }
    if !service_installed() || SERVICE_RUNNING.swap(true, Ordering::Relaxed) {
        return;
    }
    SERVICE_STOP.store(false, Ordering::Relaxed);
    std::thread::spawn(|| {
        let problem = |text: Option<String>| {
            if let Ok(mut slot) = SERVICE_PROBLEM.lock() {
                *slot = text;
            }
        };
        while !SERVICE_STOP.load(Ordering::Relaxed) {
            let owned = std::fs::symlink_metadata(SOCKET).is_ok_and(|meta| meta.uid() == 0);
            match std::os::unix::net::UnixStream::connect(SOCKET) {
                Ok(stream) if owned => {
                    let (mut uid, mut gid) = (u32::MAX, u32::MAX);
                    let root = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } == 0 && uid == 0;
                    if !root {
                        problem(Some("The sensor socket is not served by root; it was not read.".into()));
                    } else {
                        let end = stream.try_clone().ok();
                        problem(capture(stream).err());
                        if let Some(end) = end {
                            let _ = end.shutdown(std::net::Shutdown::Both);
                        }
                    }
                }
                _ => problem(Some("The sensor service is installed but not answering yet; it starts within seconds of installing.".into())),
            }
            for _ in 0..10 {
                if SERVICE_STOP.load(Ordering::Relaxed) {
                    break;
                }
                std::thread::sleep(Duration::from_secs(1));
            }
        }
        SERVICE_RUNNING.store(false, Ordering::Relaxed);
    });
}

/// The events the service handed over since the last call (also appended to `protection.events`)
/// and the sensor's state.
pub fn take() -> (Vec<SecurityObservation>, ProtectionSensor) {
    let now = crate::util::now_ms();
    let (events, last_at, dropped, stopped) = {
        let mut feed = feed();
        (feed.events.drain(..).collect::<Vec<_>>(), feed.last_at, feed.lost.saturating_add(feed.native_lost), feed.stopped)
    };
    if !events.is_empty() {
        crate::graph::append(TOPIC, events.iter().filter_map(|e| serde_json::to_value(e).ok()).collect(), 14);
    }
    let mut status = ProtectionSensor { id: "endpoint".into(), label: "Endpoint events".into(), last_at, dropped, ..Default::default() };
    if last_at == 0 {
        let problem = service_problem();
        let (state, step) = if service_installed() {
            match problem.as_deref() {
                Some(problem) => ("unavailable", problem),
                None => ("starting", "The sensor service is installed; waiting for its first events."),
            }
        } else if deep_install_command().is_some() {
            ("unavailable", "The native sensor is not installed yet. Turning on deep monitoring opens its installer; macOS asks for your password once.")
        } else {
            ("unavailable", "This build has no signed sensor to install: it needs Apple's Endpoint Security approval for the signing team first. Nothing on this Mac can turn it on until then.")
        };
        status.state = state.into();
        status.detail = step.to_owned();
        return (events, status);
    }
    status.state = if stopped {
        "unavailable"
    } else if now.saturating_sub(last_at) > FRESH_MS || dropped > 0 {
        "degraded"
    } else {
        "active"
    }
    .into();
    status.detail = format!(
        "Local metadata only. Last validated record {} seconds ago; {dropped} records lost. {}",
        now.saturating_sub(last_at) / 1000,
        if stopped {
            "The native producer ended; the sensor service is asked again within seconds."
        } else {
            "Native Endpoint Security sensor must remain running with its required permissions."
        }
    );
    (events, status)
}

/// Open the signed sensor installer (macOS asks for an administrator's approval). True when it
/// was opened.
pub fn open_installer() -> bool {
    deep_install_command().is_some_and(|command| crate::util::run("/bin/sh", &["-c", &command], Duration::from_secs(10)).is_ok_and(|out| out.ok))
}

pub fn deep_install_command() -> Option<String> {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<(Vec<u8>, Instant, bool)>>> = OnceLock::new();
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let relative = "CortexTermEventSensor.app/Contents/Resources/CortexTermEventSensor.pkg";
    let mut candidates = vec![exe.parent()?.join(relative)];
    if let Some(app) = exe.ancestors().find(|path| {
        path.file_name()
            .is_some_and(|name| name == "CortexTerm.app")
    }) {
        candidates.push(app.join("Contents/Resources/security").join(relative));
    }
    for package in candidates {
        if !trusted_path(&package) || !trusted_path(&exe) {
            continue;
        }
        let meta = std::fs::symlink_metadata(&package).ok()?;
        if !meta.is_file() || meta.nlink() != 1 || meta.len() > 128 * 1024 * 1024 {
            continue;
        }
        let own_meta = std::fs::metadata(&exe).ok()?;
        let mut digest = Sha256::new();
        digest.update(package.as_os_str().as_encoded_bytes());
        for m in [&meta, &own_meta] {
            for value in [
                m.dev(),
                m.ino(),
                m.len(),
                m.mtime() as u64,
                m.mtime_nsec() as u64,
                m.ctime() as u64,
                m.ctime_nsec() as u64,
                m.mode() as u64,
                m.uid() as u64,
                m.gid() as u64,
            ] {
                digest.update(value.to_ne_bytes());
            }
        }
        let key = digest.finalize().to_vec();
        let cache = CACHE.get_or_init(|| Mutex::new(None));
        let cached = cache.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .filter(|(old, at, _)| old == &key && at.elapsed() < Duration::from_secs(60))
                .map(|(_, _, valid)| *valid)
        });
        let valid = cached.unwrap_or_else(|| {
            let valid = (|| -> Option<()> {
                let team = expected_team(&exe)?;
                let output = crate::util::run(
                    "/usr/sbin/pkgutil",
                    &["--check-signature", package.to_str()?],
                    Duration::from_secs(5),
                )
                .ok()?;
                if !output.ok
                    || output.stdout.len() > 64 * 1024
                    || !output.stdout.contains(
                        "signed by a developer certificate issued by Apple for distribution",
                    )
                {
                    return None;
                }
                if !output.stdout.lines().any(|line| {
                    line.contains("Developer ID Installer:")
                        && line.trim_end().ends_with(&format!("({team})"))
                }) {
                    return None;
                }
                Some(())
            })()
            .is_some();
            if let Ok(mut guard) = cache.lock() {
                *guard = Some((key.clone(), Instant::now(), valid));
            }
            valid
        });
        if valid {
            return Some(format!("open -- {}", shell(&package.to_string_lossy())));
        }
    }
    None
}

fn expected_team(executable: &Path) -> Option<String> {
    signature_team(executable).or_else(|| {
        option_env!("CORTEXTERM_ES_TEAM_ID")
            .filter(|team| team.len() == 10 && team.bytes().all(|b| b.is_ascii_alphanumeric()))
            .map(str::to_owned)
    })
}

fn trusted_path(path: &Path) -> bool {
    let uid = unsafe { libc::geteuid() };
    path.is_absolute()
        && path.ancestors().all(|ancestor| {
            std::fs::symlink_metadata(ancestor).is_ok_and(|meta| {
                !meta.file_type().is_symlink()
                    && [0, uid].contains(&meta.uid())
                    && meta.mode() & if meta.uid() == 0 { 0o002 } else { 0o022 } == 0
            })
        })
}

/// The team of a valid, non-ad-hoc code signature.
fn signature_team(path: &Path) -> Option<String> {
    let text = path.to_str()?;
    let verify = crate::util::run(
        "/usr/bin/codesign",
        &["--verify", "--strict", text],
        Duration::from_secs(5),
    )
    .ok()?;
    if !verify.ok {
        return None;
    }
    let out = crate::util::run("/usr/bin/codesign", &["-dvvvv", text], Duration::from_secs(5)).ok()?;
    if !out.ok || out.stderr.contains("Signature=adhoc") {
        return None;
    }
    let team = out
        .stderr
        .lines()
        .find_map(|line| line.strip_prefix("TeamIdentifier="))?
        .trim();
    if team.len() != 10 || !team.bytes().all(|c| c.is_ascii_alphanumeric()) {
        return None;
    }
    Some(team.into())
}

/// A cleaned event for the collector; the oldest waiting one is lost when the queue is full.
fn deliver(event: SecurityObservation, native_lost: u64) {
    let mut feed = feed();
    if feed.events.len() >= MAX_WAITING {
        feed.events.pop_front();
        feed.lost = feed.lost.saturating_add(1);
    }
    feed.events.push_back(event);
    feed.native_lost = feed.native_lost.max(native_lost);
}

fn lost() {
    let mut feed = feed();
    feed.lost = feed.lost.saturating_add(1);
}

/// The native helper's schema-1 records from the sensor service's socket, cleaned, to the
/// collector, until deep monitoring is turned off or the service ends the connection.
fn capture<R: std::io::Read + Send + 'static>(reader: R) -> Result<(), String> {
    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(256);
    let dropped = Arc::new(AtomicU64::new(0));
    let loss = dropped.clone();
    std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = Vec::new();
        loop {
            line.clear();
            let mut oversized = false;
            loop {
                let available = match reader.fill_buf() {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        loss.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                if available.is_empty() {
                    return;
                }
                let count = available
                    .iter()
                    .position(|b| *b == b'\n')
                    .map_or(available.len(), |n| n + 1);
                let finished = available.get(count - 1) == Some(&b'\n');
                if line.len() + count <= MAX_LINE && !oversized {
                    line.extend_from_slice(&available[..count]);
                } else {
                    oversized = true;
                    line.clear();
                }
                reader.consume(count);
                if finished {
                    break;
                }
            }
            if oversized {
                loss.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            match sender.try_send(std::mem::take(&mut line)) {
                Ok(()) => (),
                Err(mpsc::TrySendError::Full(_)) => {
                    loss.fetch_add(1, Ordering::Relaxed);
                }
                Err(mpsc::TrySendError::Disconnected(_)) => return,
            }
        }
    });
    let mut native_dropped = 0u64;
    let mut received = false;
    // Retain fixed-size path hashes for distinct counts, not thousands of long private paths.
    let mut changes: HashMap<String, (Instant, BTreeSet<[u8; 32]>, bool)> = HashMap::new();
    loop {
        // Losses on the way from the socket count once, as they happen.
        let reader_lost = dropped.swap(0, Ordering::Relaxed);
        if reader_lost > 0 {
            let mut feed = feed();
            feed.lost = feed.lost.saturating_add(reader_lost);
        }
        if SERVICE_STOP.load(Ordering::Relaxed) {
            return Ok(());
        }
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(line) => {
                let value: Value = match serde_json::from_slice(&line) {
                    Ok(value) => value,
                    Err(_) => {
                        lost();
                        continue;
                    }
                };
                let now = crate::util::now_ms();
                let valid_time = value["at"]
                    .as_u64()
                    .is_some_and(|at| at <= now + 60_000 && now.saturating_sub(at) < FRESH_MS);
                if value["schema"] != 1 || !valid_time {
                    lost();
                    continue;
                }
                if value["record"] == "error" {
                    return Err(value["text"].as_str().unwrap_or("The sensor could not start.").chars().take(300).collect());
                }
                received = true;
                native_dropped = value["dropped"].as_u64().unwrap_or(native_dropped);
                {
                    let mut feed = feed();
                    feed.last_at = now;
                    feed.stopped = false;
                    feed.native_lost = feed.native_lost.max(native_dropped);
                }
                if value["record"] == "heartbeat" {
                    continue;
                }
                let Some(event) = input::endpoint_observation(&value["observation"]) else {
                    lost();
                    continue;
                };
                if event.at > now + 60_000 || now.saturating_sub(event.at) > FRESH_MS {
                    lost();
                    continue;
                }
                changes.retain(|_, (at, _, _)| at.elapsed() < Duration::from_secs(30));
                if matches!(
                    event.kind.as_str(),
                    "file_write" | "file_rename" | "file_unlink"
                ) {
                    if changes.len() >= 1024 && !changes.contains_key(&event.subject) {
                        lost();
                        continue;
                    }
                    let bucket = changes
                        .entry(event.subject.clone())
                        .or_insert_with(|| (Instant::now(), BTreeSet::new(), false));
                    if let Some(path) = &event.path {
                        if bucket.1.len() < 256 {
                            bucket.1.insert(Sha256::digest(path.as_bytes()).into());
                        }
                    }
                    if bucket.1.len() >= 50 && !bucket.2 {
                        bucket.2 = true;
                        let mut bulk = event.clone();
                        bulk.kind = "bulk_file_change".into();
                        bulk.severity = "medium".into();
                        bulk.rule = "endpoint.bulk_file_change".into();
                        bulk.summary = "A process modified, renamed or removed at least 50 different home-directory files within 30 seconds. This may be a normal batch operation; the file changes alone do not establish ransomware.".into();
                        bulk.count = bucket.1.len() as u64;
                        deliver(bulk, native_dropped);
                    }
                    // Keep a small sample of the actual changed paths, not every write.
                    if bucket.1.len() > 5 {
                        continue;
                    }
                }
                deliver(event, native_dropped);
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if !received {
                    return Err("The native producer ended without a valid record. Check its entitlement, Full Disk Access permission and administrator authorization.".into());
                }
                feed().stopped = true;
                return Ok(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }
    }
}

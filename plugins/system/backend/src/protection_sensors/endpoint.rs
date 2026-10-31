//! User-authorized native Endpoint Security capture. The privileged helper has one job: emit
//! allow-listed metadata. This unprivileged sink removes all unrecognized fields before writing.

use super::input;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

const FILE_LIMIT: u64 = 16 * 1024 * 1024;
const MAX_LINE: usize = 64 * 1024;
static STOP_CAPTURE: AtomicBool = AtomicBool::new(false);

extern "C" fn request_stop(_signal: libc::c_int) {
    STOP_CAPTURE.store(true, Ordering::Relaxed);
}

struct SignalGuard {
    interrupt: libc::sighandler_t,
    terminate: libc::sighandler_t,
}
impl Drop for SignalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::signal(libc::SIGINT, self.interrupt);
            libc::signal(libc::SIGTERM, self.terminate);
        }
    }
}

fn shell(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

const INSTALLED_HELPER: &str = "/Library/Application Support/CortexTerm/Security/CortexTermEventSensor.app/Contents/MacOS/cortexterm-event-sensor";

/// The producer elevated by this command must be installed in the fixed root-owned location.
/// A mutable plugin asset, unsigned build, or unprovisioned helper is never offered to sudo.
pub fn deep_capture_command() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let exe = std::env::current_exe().ok()?;
    let helper = Path::new(INSTALLED_HELPER);
    if !root_helper_path(helper) || !helper_trusted(helper, &exe) {
        return None;
    }
    let uid = unsafe { libc::geteuid() };
    if uid == 0 {
        return None;
    }
    let dir = crate::util::data_dir();
    let home = std::fs::canonicalize(crate::util::home()).ok()?;
    Some(format!(
        "mkdir -p -m 700 {} && sudo {} --uid {uid} --home {} --exclude-path {} | env CORTEX_PLUGIN_DATA={} {} --security-events",
        shell(&dir.to_string_lossy()),
        shell(&helper.to_string_lossy()),
        shell(&home.to_string_lossy()),
        shell(&dir.to_string_lossy()),
        shell(&dir.to_string_lossy()),
        shell(&exe.to_string_lossy())
    ))
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

fn root_helper_path(path: &Path) -> bool {
    path == Path::new(INSTALLED_HELPER)
        && path.ancestors().all(|ancestor| {
            std::fs::symlink_metadata(ancestor).is_ok_and(|meta| {
                !meta.file_type().is_symlink() && meta.uid() == 0 && meta.mode() & 0o022 == 0
            })
        })
}

fn expected_team(executable: &Path) -> Option<String> {
    signature(executable).map(|(team, _)| team).or_else(|| {
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

fn signature(path: &Path) -> Option<(String, plist::Dictionary)> {
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
    let out = crate::util::run(
        "/usr/bin/codesign",
        &["-dvvvv", "--entitlements", "-", "--xml", text],
        Duration::from_secs(5),
    )
    .ok()?;
    if !out.ok || out.stderr.contains("Signature=adhoc") || out.stdout.len() > 256 * 1024 {
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
    let identifier = out
        .stderr
        .lines()
        .find_map(|line| line.strip_prefix("Identifier="))?
        .trim();
    let mut entitlements = if out.stdout.trim().is_empty() {
        plist::Dictionary::new()
    } else {
        match plist::Value::from_reader_xml(out.stdout.as_bytes()).ok()? {
            plist::Value::Dictionary(dict) => dict,
            _ => return None,
        }
    };
    entitlements.insert(
        "__identifier".into(),
        plist::Value::String(identifier.into()),
    );
    Some((team.into(), entitlements))
}

fn helper_trusted(path: &Path, own_executable: &Path) -> bool {
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<Option<(Vec<u8>, Instant, bool)>>> = OnceLock::new();
    let Some(contents) = path.parent().and_then(Path::parent) else {
        return false;
    };
    let Some(bundle) = contents.parent() else {
        return false;
    };
    let profile = contents.join("embedded.provisionprofile");
    if !root_helper_path(path) || !trusted_path(own_executable) {
        return false;
    }
    let Ok(meta) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !meta.is_file() || meta.mode() & 0o111 == 0 || meta.len() > 64 * 1024 * 1024 {
        return false;
    }
    let Ok(profile_meta) = std::fs::symlink_metadata(&profile) else {
        return false;
    };
    if !profile_meta.is_file() || profile_meta.len() > 1024 * 1024 || profile_meta.nlink() != 1 {
        return false;
    }
    if profile_meta.uid() != 0 || profile_meta.mode() & 0o022 != 0 {
        return false;
    }
    let mut digest = Sha256::new();
    // File replacement, profile replacement and a signed bundle update invalidate the cache.
    for item in [path, own_executable, profile.as_path(), bundle] {
        let Ok(meta) = std::fs::symlink_metadata(item) else {
            return false;
        };
        digest.update(item.as_os_str().as_encoded_bytes());
        for value in [
            meta.dev(),
            meta.ino(),
            meta.len(),
            meta.mtime() as u64,
            meta.mtime_nsec() as u64,
            meta.ctime() as u64,
            meta.ctime_nsec() as u64,
            meta.mode() as u64,
            meta.uid() as u64,
            meta.gid() as u64,
        ] {
            digest.update(value.to_ne_bytes());
        }
    }
    let key = digest.finalize().to_vec();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some((old, checked, valid)) = &*guard {
            if *old == key && checked.elapsed() < Duration::from_secs(60) {
                return *valid;
            }
        }
    }
    let valid = (|| -> Option<()> {
        let (team, entitlements) = signature(path)?;
        let own_team = expected_team(own_executable)?;
        if team != own_team
            || entitlements.get("__identifier")?.as_string()? != "ai.cortexterm.event-sensor"
            || entitlements
                .get("com.apple.developer.endpoint-security.client")?
                .as_boolean()?
                != true
        {
            return None;
        }
        let bundle_check = crate::util::run(
            "/usr/bin/codesign",
            &["--verify", "--strict", bundle.to_str()?],
            Duration::from_secs(5),
        )
        .ok()?;
        if !bundle_check.ok {
            return None;
        }
        let decoded = crate::util::run(
            "/usr/bin/security",
            &["cms", "-D", "-i", profile.to_str()?],
            Duration::from_secs(5),
        )
        .ok()?;
        if !decoded.ok || decoded.stdout.len() > 1024 * 1024 {
            return None;
        }
        let profile = plist::Value::from_reader_xml(decoded.stdout.as_bytes()).ok()?;
        let dictionary = profile.as_dictionary()?;
        let expiry: std::time::SystemTime = dictionary.get("ExpirationDate")?.as_date()?.into();
        if expiry <= std::time::SystemTime::now() {
            return None;
        }
        let permits = dictionary.get("Entitlements")?.as_dictionary()?;
        let expected = format!("{team}.ai.cortexterm.event-sensor");
        if permits
            .get("com.apple.developer.endpoint-security.client")?
            .as_boolean()?
            != true
            || permits
                .get("com.apple.application-identifier")?
                .as_string()?
                != expected
        {
            return None;
        }
        Some(())
    })()
    .is_some();
    if let Ok(mut guard) = cache.lock() {
        *guard = Some((key, Instant::now(), valid));
    }
    valid
}

fn secure_dir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("Cannot create private capture directory: {e}"))?;
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !meta.is_dir()
        || meta.file_type().is_symlink()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o022 != 0
    {
        return Err("Capture directory must be owned by you and not writable by group or others; symbolic links are refused.".into());
    }
    Ok(())
}

fn output(path: &Path) -> Result<File, String> {
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err(
            "Capture output must be a private, single-link regular file owned by you.".into(),
        );
    }
    Ok(file)
}

struct Sink {
    file: File,
    path: PathBuf,
    bytes: u64,
}
impl Sink {
    fn write(&mut self, value: Value) -> Result<(), String> {
        let mut line = serde_json::to_vec(&value).map_err(|e| e.to_string())?;
        line.push(b'\n');
        if self.bytes.saturating_add(line.len() as u64) > FILE_LIMIT {
            self.file.sync_data().map_err(|e| e.to_string())?;
            std::fs::rename(&self.path, self.path.with_extension("jsonl.1"))
                .map_err(|e| e.to_string())?;
            self.file = output(&self.path)?;
            self.bytes = 0;
        }
        self.file.write_all(&line).map_err(|e| e.to_string())?;
        self.file.flush().map_err(|e| e.to_string())?;
        self.bytes = self.bytes.saturating_add(line.len() as u64);
        Ok(())
    }
}

/// Stdin contains only the native helper's schema-1 records. Never run this sink with sudo:
/// the generated pipeline elevates the native producer alone. EOF stops capture immediately.
pub fn endpoint_capture() -> Result<(), String> {
    if unsafe { libc::geteuid() } == 0 {
        return Err(
            "Run the capture sink as your normal user; only the native producer needs sudo.".into(),
        );
    }
    STOP_CAPTURE.store(false, Ordering::Relaxed);
    let signals = unsafe {
        SignalGuard {
            interrupt: libc::signal(libc::SIGINT, request_stop as libc::sighandler_t),
            terminate: libc::signal(libc::SIGTERM, request_stop as libc::sighandler_t),
        }
    };
    if signals.interrupt == libc::SIG_ERR || signals.terminate == libc::SIG_ERR {
        return Err("Cannot install the capture shutdown handlers.".into());
    }
    let _signals = signals;
    let dir = crate::util::data_dir();
    secure_dir(&dir)?;
    let lock_path = dir.join("protection-events.lock");
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(lock_path)
        .map_err(|e| e.to_string())?;
    let meta = lock.metadata().map_err(|e| e.to_string())?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o077 != 0
        || meta.nlink() != 1
    {
        return Err("Capture lock is not a private regular file.".into());
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("Another endpoint capture is already running.".into());
    }
    let path = dir.join("protection-events.jsonl");
    let file = output(&path)?;
    let bytes = file.metadata().map_err(|e| e.to_string())?.len();
    let mut sink = Sink { file, path, bytes };
    let (sender, receiver) = mpsc::sync_channel::<Vec<u8>>(256);
    let dropped = Arc::new(AtomicU64::new(0));
    let loss = dropped.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut reader = BufReader::new(stdin.lock());
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
    let mut last_native = 0u64;
    let mut last_beat = Instant::now();
    // Retain fixed-size path hashes for distinct counts, not thousands of long private paths.
    let mut changes: HashMap<String, (Instant, BTreeSet<[u8; 32]>, bool)> = HashMap::new();
    loop {
        if STOP_CAPTURE.load(Ordering::Relaxed) {
            sink.write(json!({"schema":1,"record":"stopped","at":crate::util::now_ms(),"dropped":native_dropped.saturating_add(dropped.load(Ordering::Relaxed))}))?;
            return Ok(());
        }
        if last_beat.elapsed() >= Duration::from_secs(5) {
            if last_native > 0 && crate::util::now_ms().saturating_sub(last_native) < 15_000 {
                sink.write(json!({"schema":1,"record":"heartbeat","at":last_native,"dropped":native_dropped.saturating_add(dropped.load(Ordering::Relaxed))}))?;
            }
            last_beat = Instant::now();
        }
        match receiver.recv_timeout(Duration::from_secs(1)) {
            Ok(line) => {
                let value: Value = match serde_json::from_slice(&line) {
                    Ok(value) => value,
                    Err(_) => {
                        dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                };
                let now = crate::util::now_ms();
                let valid_time = value["at"]
                    .as_u64()
                    .is_some_and(|at| at <= now + 60_000 && now.saturating_sub(at) < 120_000);
                if value["schema"] != 1 || !valid_time {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                last_native = now;
                native_dropped = value["dropped"].as_u64().unwrap_or(native_dropped);
                if value["record"] == "heartbeat" {
                    continue;
                }
                let Some(mut event) = input::endpoint_observation(&value["observation"]) else {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if event.at > now + 60_000 || now.saturating_sub(event.at) > 120_000 {
                    dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                }
                changes.retain(|_, (at, _, _)| at.elapsed() < Duration::from_secs(30));
                if matches!(
                    event.kind.as_str(),
                    "file_write" | "file_rename" | "file_unlink"
                ) {
                    if changes.len() >= 1024 && !changes.contains_key(&event.subject) {
                        dropped.fetch_add(1, Ordering::Relaxed);
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
                        event.kind = "bulk_file_change".into();
                        event.severity = "medium".into();
                        event.rule = "endpoint.bulk_file_change".into();
                        event.summary = "A process modified, renamed or removed at least 50 different home-directory files within 30 seconds. This may be a normal batch operation; the file changes alone do not establish ransomware.".into();
                        event.count = bucket.1.len() as u64;
                        sink.write(json!({"schema":1,"record":"event","at":now,"dropped":native_dropped.saturating_add(dropped.load(Ordering::Relaxed)),"observation":event}))?;
                    }
                    // Keep a small sample of the actual changed paths, not every write.
                    if bucket.1.len() > 5 {
                        continue;
                    }
                }
                sink.write(json!({"schema":1,"record":"event","at":now,"dropped":native_dropped.saturating_add(dropped.load(Ordering::Relaxed)),"observation":event}))?;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if last_native == 0 {
                    return Err("The native producer ended without a valid record. Check its entitlement, Full Disk Access permission and administrator authorization.".into());
                }
                sink.write(json!({"schema":1,"record":"stopped","at":crate::util::now_ms(),"dropped":native_dropped.saturating_add(dropped.load(Ordering::Relaxed))}))?;
                return Ok(());
            }
            Err(mpsc::RecvTimeoutError::Timeout) => (),
        }
    }
}

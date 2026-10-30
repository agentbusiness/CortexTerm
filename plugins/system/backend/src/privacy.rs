//! Spyware and privacy: programs that watch the keyboard (event taps, the ReiKey technique),
//! whether a camera or microphone is in use right now, who holds the strong privacy permissions
//! (the TCC databases, readable with Full Disk Access), and a guided check of iPhone backups with
//! Amnesty's MVT.

use crate::sweep::Part;
use crate::util::{home, plural, run, tilde};
use crate::{codesign, malware};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub fn checks() -> Part {
    let mut part = Part::default();
    if !cfg!(target_os = "macos") {
        part.skipped.push("privacy checks: not a Mac".into());
        return part;
    }
    keyboard_taps(&mut part);
    devices(&mut part);
    permissions(&mut part);
    iphone_backups(&mut part);
    part
}

// --- 47. Keyboard event taps.

/// One event tap that sees key presses: who installed it.
pub struct Tap {
    pub pid: i32,
    /// Listens only (cannot change events).
    pub listen_only: bool,
}

#[cfg(target_os = "macos")]
mod ffi {
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct CGEventTapInformation {
        pub event_tap_id: u32,
        pub tap_point: u32,
        pub options: u32,
        pub events_of_interest: u64,
        pub tapping_process: i32,
        pub process_being_tapped: i32,
        pub enabled: bool,
        pub min_usec_latency: f32,
        pub avg_usec_latency: f32,
        pub max_usec_latency: f32,
    }

    #[repr(C)]
    pub struct PropertyAddress {
        pub selector: u32,
        pub scope: u32,
        pub element: u32,
    }

    #[link(name = "CoreGraphics", kind = "framework")]
    unsafe extern "C" {
        pub fn CGGetEventTapList(max: u32, list: *mut CGEventTapInformation, count: *mut u32) -> i32;
    }

    #[link(name = "CoreAudio", kind = "framework")]
    unsafe extern "C" {
        pub fn AudioObjectGetPropertyDataSize(object: u32, address: *const PropertyAddress, qualifier_size: u32, qualifier: *const std::ffi::c_void, size: *mut u32) -> i32;
        pub fn AudioObjectGetPropertyData(object: u32, address: *const PropertyAddress, qualifier_size: u32, qualifier: *const std::ffi::c_void, size: *mut u32, data: *mut std::ffi::c_void) -> i32;
    }

    #[link(name = "CoreMediaIO", kind = "framework")]
    unsafe extern "C" {
        pub fn CMIOObjectGetPropertyDataSize(object: u32, address: *const PropertyAddress, qualifier_size: u32, qualifier: *const std::ffi::c_void, size: *mut u32) -> i32;
        pub fn CMIOObjectGetPropertyData(object: u32, address: *const PropertyAddress, qualifier_size: u32, qualifier: *const std::ffi::c_void, size: u32, used: *mut u32, data: *mut std::ffi::c_void) -> i32;
    }

    pub const fn code(text: &[u8; 4]) -> u32 {
        u32::from_be_bytes(*text)
    }
}

/// Every event tap that sees key presses (key down, key up or modifier changes).
#[cfg(target_os = "macos")]
pub fn keyboard_tap_list() -> Option<Vec<Tap>> {
    const KEYS: u64 = (1 << 10) | (1 << 11) | (1 << 12);
    let mut count = 0u32;
    // SAFETY: a null list asks only for the count.
    if unsafe { ffi::CGGetEventTapList(0, std::ptr::null_mut(), &mut count) } != 0 {
        return None;
    }
    let mut list = vec![ffi::CGEventTapInformation::default(); count as usize];
    // SAFETY: `list` has room for `count` entries.
    if unsafe { ffi::CGGetEventTapList(count, list.as_mut_ptr(), &mut count) } != 0 {
        return None;
    }
    list.truncate(count as usize);
    Some(
        list.iter()
            .filter(|t| t.enabled && t.events_of_interest & KEYS != 0)
            .map(|t| Tap { pid: t.tapping_process, listen_only: t.options == 1 })
            .collect(),
    )
}

#[cfg(not(target_os = "macos"))]
pub fn keyboard_tap_list() -> Option<Vec<Tap>> {
    None
}

/// Apps known to watch the keyboard for shortcuts.
const KNOWN_TAPPERS: [&str; 14] = [
    "Karabiner", "Raycast", "Alfred", "BetterTouchTool", "Rectangle", "Hammerspoon", "Keyboard Maestro", "BetterSnapTool",
    "Magnet", "Contexts", "TextExpander", "Espanso", "Typinator", "skhd",
];

fn exe_of(pid: i32) -> String {
    #[cfg(target_os = "macos")]
    {
        libproc::libproc::proc_pid::pidpath(pid).unwrap_or_default()
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| p.display().to_string()).unwrap_or_default()
    }
}

fn keyboard_taps(part: &mut Part) {
    let Some(taps) = keyboard_tap_list() else {
        part.skipped.push("keyboard watchers: CoreGraphics did not list the event taps".into());
        return;
    };
    part.checked.push(format!("keyboard watchers ({})", plural(taps.len(), "event tap sees", "event taps see")));
    let mut seen = BTreeSet::new();
    for tap in &taps {
        if !seen.insert(tap.pid) {
            continue;
        }
        let exe = exe_of(tap.pid);
        let path = Path::new(&exe);
        let sig = codesign::check(path);
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| format!("pid {}", tap.pid));
        let how = if tap.listen_only { "reads" } else { "can read and change" };
        // macOS's own taps (input methods, accessibility) are not news.
        if !exe.is_empty() && sig.apple {
            continue;
        }
        let (severity, verdict) = if exe.is_empty() {
            ("medium", "a process CortexTerm cannot name".to_owned())
        } else if KNOWN_TAPPERS.iter().any(|k| exe.contains(k)) {
            ("info", format!("{} (a known shortcut app)", tilde(path)))
        } else if sig.unsigned() {
            ("high", format!("{}, which is {}", tilde(path), if sig.status == "adhoc" { "only ad-hoc signed" } else { "not signed" }))
        } else if sig.team_id.is_empty() {
            ("medium", format!("{}, whose signer could not be told", tilde(path)))
        } else {
            ("low", format!("{} (signed, team {})", tilde(path), sig.team_id))
        };
        let warning = if severity == "info" { "" } else { " If you do not know it, it may be a keylogger." };
        part.add(
            severity,
            "privacy",
            format!("{name} (pid {}) {how} every key you type: {verdict}.{warning}", tap.pid),
            None,
            "event taps",
        );
    }
}

// --- 48. Camera and microphone in use.

/// (device name, in use) for every audio input device.
#[cfg(target_os = "macos")]
pub fn microphones() -> Vec<(String, bool)> {
    use ffi::*;
    let global = code(b"glob");
    let devices_address = PropertyAddress { selector: code(b"dev#"), scope: global, element: 0 };
    let mut size = 0u32;
    // SAFETY: plain CoreAudio property reads into buffers of the size it reports.
    unsafe {
        if AudioObjectGetPropertyDataSize(1, &devices_address, 0, std::ptr::null(), &mut size) != 0 {
            return Vec::new();
        }
        let mut ids = vec![0u32; size as usize / 4];
        if AudioObjectGetPropertyData(1, &devices_address, 0, std::ptr::null(), &mut size, ids.as_mut_ptr().cast()) != 0 {
            return Vec::new();
        }
        let mut out = Vec::new();
        for id in ids {
            let streams = PropertyAddress { selector: code(b"stm#"), scope: code(b"inpt"), element: 0 };
            let mut stream_size = 0u32;
            if AudioObjectGetPropertyDataSize(id, &streams, 0, std::ptr::null(), &mut stream_size) != 0 || stream_size == 0 {
                continue;
            }
            let running = PropertyAddress { selector: code(b"gone"), scope: global, element: 0 };
            let mut on = 0u32;
            let mut on_size = 4u32;
            let _ = AudioObjectGetPropertyData(id, &running, 0, std::ptr::null(), &mut on_size, (&mut on as *mut u32).cast());
            out.push((audio_name(id), on != 0));
        }
        out
    }
}

#[cfg(target_os = "macos")]
unsafe fn audio_name(id: u32) -> String {
    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    let address = ffi::PropertyAddress { selector: ffi::code(b"lnam"), scope: ffi::code(b"glob"), element: 0 };
    let mut name: CFStringRef = std::ptr::null();
    let mut size = std::mem::size_of::<CFStringRef>() as u32;
    // SAFETY: the property is a CFString the caller owns.
    unsafe {
        if ffi::AudioObjectGetPropertyData(id, &address, 0, std::ptr::null(), &mut size, (&mut name as *mut CFStringRef).cast()) != 0 || name.is_null() {
            return format!("audio device {id}");
        }
        CFString::wrap_under_create_rule(name).to_string()
    }
}

/// (device name, in use) for every camera.
#[cfg(target_os = "macos")]
pub fn cameras() -> Vec<(String, bool)> {
    use core_foundation::base::TCFType;
    use core_foundation::string::{CFString, CFStringRef};
    use ffi::*;
    let global = code(b"glob");
    let devices_address = PropertyAddress { selector: code(b"dev#"), scope: global, element: 0 };
    let mut size = 0u32;
    // SAFETY: plain CoreMediaIO property reads into buffers of the size it reports.
    unsafe {
        if CMIOObjectGetPropertyDataSize(1, &devices_address, 0, std::ptr::null(), &mut size) != 0 {
            return Vec::new();
        }
        let mut ids = vec![0u32; size as usize / 4];
        let mut used = 0u32;
        if CMIOObjectGetPropertyData(1, &devices_address, 0, std::ptr::null(), size, &mut used, ids.as_mut_ptr().cast()) != 0 {
            return Vec::new();
        }
        ids.truncate(used as usize / 4);
        let mut out = Vec::new();
        for id in ids {
            let running = PropertyAddress { selector: code(b"gone"), scope: global, element: 0 };
            let mut on = 0u32;
            let _ = CMIOObjectGetPropertyData(id, &running, 0, std::ptr::null(), 4, &mut used, (&mut on as *mut u32).cast());
            let name_address = PropertyAddress { selector: code(b"lnam"), scope: global, element: 0 };
            let mut name: CFStringRef = std::ptr::null();
            let ok = CMIOObjectGetPropertyData(id, &name_address, 0, std::ptr::null(), std::mem::size_of::<CFStringRef>() as u32, &mut used, (&mut name as *mut CFStringRef).cast()) == 0;
            let name = if ok && !name.is_null() { CFString::wrap_under_create_rule(name).to_string() } else { format!("camera {id}") };
            out.push((name, on != 0));
        }
        out
    }
}

#[cfg(not(target_os = "macos"))]
pub fn microphones() -> Vec<(String, bool)> {
    Vec::new()
}

#[cfg(not(target_os = "macos"))]
pub fn cameras() -> Vec<(String, bool)> {
    Vec::new()
}


fn devices(part: &mut Part) {
    let (cams, mics) = (cameras(), microphones());
    part.checked.push(format!("camera and microphone use ({} and {})", plural(cams.len(), "camera", "cameras"), plural(mics.len(), "microphone", "microphones")));
    for (kind, list) in [("camera", cams), ("microphone", mics)] {
        for (name, _) in list.into_iter().filter(|(_, on)| *on) {
            part.add(
                "medium",
                "privacy",
                format!("The {kind} {name} was in use during the sweep. If you were not in a call or recording, check which app uses it (Control Center shows it)."),
                None,
                "devices",
            );
        }
    }
}

// --- 49. Privacy permissions (TCC).

/// The services worth a look, and what they let a program do.
const SERVICES: [(&str, &str); 8] = [
    ("kTCCServiceSystemPolicyAllFiles", "read every file (Full Disk Access)"),
    ("kTCCServiceAccessibility", "control the computer (Accessibility)"),
    ("kTCCServiceScreenCapture", "record the screen"),
    ("kTCCServiceListenEvent", "read every key you type (Input Monitoring)"),
    ("kTCCServicePostEvent", "type and click for you"),
    ("kTCCServiceCamera", "use the camera"),
    ("kTCCServiceMicrophone", "use the microphone"),
    ("kTCCServiceAppleEvents", "control other apps (Automation)"),
];

const FDA_PANE: &str = "open \"x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles\"";

/// (service, client, client is a path) granted in one TCC database.
fn grants(db: &Path) -> Result<Vec<(String, String, bool)>, String> {
    let db = rusqlite::Connection::open_with_flags(db, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX)
        .map_err(|e| e.to_string())?;
    let mut query = db.prepare("SELECT service, client, client_type FROM access WHERE auth_value = 2").map_err(|e| e.to_string())?;
    let rows = query.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, r.get::<_, i64>(2)? == 1))).map_err(|e| e.to_string())?;
    Ok(rows.flatten().collect())
}

/// Where an app with this bundle id lives (Spotlight), when it is installed.
fn app_path(bundle: &str) -> Option<PathBuf> {
    let query = format!("kMDItemCFBundleIdentifier == '{}'", bundle.replace('\'', ""));
    let out = run("/usr/bin/mdfind", &[&query], Duration::from_secs(5)).ok()?;
    out.stdout.lines().map(PathBuf::from).find(|p| p.exists())
}

fn permissions(part: &mut Part) {
    let dbs = [home().join("Library/Application Support/com.apple.TCC/TCC.db"), PathBuf::from("/Library/Application Support/com.apple.TCC/TCC.db")];
    let mut all = Vec::new();
    for db in &dbs {
        match grants(db) {
            Ok(list) => all.extend(list),
            Err(_) => {
                part.skipped.push(format!("privacy permissions in {}: needs Full Disk Access for CortexTerm", tilde(db)));
                if all.is_empty() && db == &dbs[0] {
                    part.add(
                        "info",
                        "privacy",
                        "CortexTerm cannot see which programs hold privacy permissions (Full Disk Access, Accessibility, Screen Recording, Input Monitoring) without Full Disk Access. Give it in System Settings to have this checked.".into(),
                        Some(FDA_PANE.into()),
                        "tcc",
                    );
                }
            }
        }
    }
    // client -> (is a path, what it may do, the worst service's severity)
    let mut clients: std::collections::BTreeMap<String, (bool, Vec<&str>, &str)> = Default::default();
    let mut grants_seen = 0;
    for (service, client, is_path) in all {
        let Some((_, what)) = SERVICES.iter().find(|(s, _)| *s == service) else { continue };
        grants_seen += 1;
        let entry = clients.entry(client).or_insert((is_path, Vec::new(), "medium"));
        if !entry.1.contains(what) {
            entry.1.push(what);
        }
        if matches!(service.as_str(), "kTCCServiceListenEvent" | "kTCCServiceScreenCapture" | "kTCCServiceSystemPolicyAllFiles" | "kTCCServiceAccessibility") {
            entry.2 = "high";
        }
    }
    if clients.is_empty() {
        return;
    }
    part.checked.push(format!("privacy permissions ({} to {})", plural(grants_seen, "strong grant", "strong grants"), plural(clients.len(), "program", "programs")));
    let mut looked = 0;
    for (client, (is_path, whats, severity)) in clients {
        let what = whats.join(", ");
        // A copy an app made of itself while updating (Chrome and Brave do), gone once it finished.
        if client.contains("code_sign_clone") {
            continue;
        }
        let path = if is_path {
            Some(PathBuf::from(&client))
        } else if client.starts_with("com.apple.") {
            continue;
        } else {
            looked += 1;
            if looked > 60 {
                continue;
            }
            app_path(&client)
        };
        let Some(path) = path.filter(|p| p.exists()) else {
            part.add(
                "low",
                "privacy",
                format!("{client} is no longer on this Mac but still has permission to {what}; remove it in System Settings."),
                None,
                "tcc",
            );
            continue;
        };
        let sig = codesign::check(&path);
        if sig.apple || !sig.unsigned() && sig.status != "unknown" {
            continue;
        }
        let state = match sig.status.as_str() {
            "adhoc" => "only ad-hoc signed",
            "unsigned" => "not signed",
            _ => "of unknown signature",
        };
        part.add(severity, "privacy", format!("{} has permission to {what} and is {state}.", tilde(&path)), None, "tcc");
    }
}

// --- 50. iPhone backups and MVT.

fn iphone_backups(part: &mut Part) {
    let dir = home().join("Library/Application Support/MobileSync/Backup");
    let backups: Vec<PathBuf> = std::fs::read_dir(&dir).into_iter().flatten().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    if backups.is_empty() {
        part.skipped.push("iPhone spyware check: there is no iPhone backup on this Mac (or it needs Full Disk Access to see)".into());
        return;
    }
    part.checked.push(format!("iPhone backups ({})", backups.len()));
    for backup in backups.iter().take(5) {
        let id = backup.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        part.add(
            "info",
            "privacy",
            format!(
                "There is an iPhone backup ({id}). Amnesty's Mobile Verification Toolkit can check it for known mercenary spyware such as Pegasus. An encrypted backup must first be decrypted with its password (mvt-ios decrypt-backup -d <folder> <backup>), then checked from that folder."
            ),
            Some(format!("pipx install mvt && mvt-ios download-iocs && mvt-ios check-backup {}", malware::quote(backup))),
            "mvt",
        );
    }
}

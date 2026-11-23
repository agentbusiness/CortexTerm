//! Code signatures: who signed a program or app, whether Apple notarized it, and which risky
//! entitlements it carries. Results are cached by path and modification time.

use crate::util::run;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};

/// Entitlements that weaken the hardened runtime: code can be injected or patched in.
const RISKY: [&str; 6] = [
    "com.apple.security.cs.disable-library-validation",
    "com.apple.security.cs.allow-dyld-environment-variables",
    "com.apple.security.cs.allow-unsigned-executable-memory",
    "com.apple.security.cs.disable-executable-page-protection",
    "com.apple.security.get-task-allow",
    "com.apple.security.cs.debugger",
];

#[derive(Clone, Debug, Default)]
pub struct Signature {
    /// signed | adhoc | unsigned | unknown (`unknown` also when the file does not exist)
    pub status: String,
    /// The team identifier, empty when there is none.
    pub team_id: String,
    /// The signing identifier (usually the bundle id).
    pub identifier: String,
    /// The leaf certificate, e.g. "Developer ID Application: Example Ltd (ABCD123456)".
    pub authority: String,
    /// Signed by Apple itself (system binaries and Apple's own apps).
    pub apple: bool,
    pub hardened_runtime: bool,
    /// Risky entitlements it has (short names, e.g. `cs.disable-library-validation`).
    pub risky: Vec<String>,
    /// Whether Gatekeeper accepts it as notarized or from the App Store; `None` when
    /// [`check`] made it (ask [`notarized`]).
    pub notarized: Option<bool>,
}

impl Signature {
    /// Not properly signed (unsigned or ad-hoc).
    pub fn unsigned(&self) -> bool {
        self.status == "unsigned" || self.status == "adhoc"
    }

    /// Who signed it, in words: "Apple", the certificate ("Developer ID Application: Example Ltd
    /// (ABCD123456)"), else the team; empty when nobody did.
    pub fn signer(&self) -> String {
        if self.status != "signed" {
            String::new()
        } else if self.apple {
            "Apple".into()
        } else if !self.authority.is_empty() {
            self.authority.clone()
        } else {
            self.team_id.clone()
        }
    }
}

/// A file's modification time and size: a cached answer holds while they do.
type Stamp = (Option<SystemTime>, u64);

type Cache<T> = Mutex<HashMap<PathBuf, (Stamp, T)>>;

fn cache() -> &'static Cache<Signature> {
    static CACHE: OnceLock<Cache<Signature>> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn cached<T: Clone>(cache: &Cache<T>, path: &Path, stamp: Stamp) -> Option<T> {
    let cache = cache.lock().ok()?;
    let (when, value) = cache.get(path)?;
    (*when == stamp).then(|| value.clone())
}

fn store<T: Clone>(cache: &Cache<T>, path: &Path, stamp: Stamp, value: &T) {
    if let Ok(mut cache) = cache.lock() {
        cache.insert(path.to_path_buf(), (stamp, value.clone()));
    }
}

fn stamp(path: &Path) -> Stamp {
    match std::fs::metadata(path) {
        Ok(meta) => (meta.modified().ok(), meta.len()),
        Err(_) => (None, 0),
    }
}

/// Who vouches for a file: the app or other bundle it is part of (or the file itself), signed by
/// Apple or a named developer, with its seal intact (`codesign --verify --strict`, slow). The
/// signer ("Apple", the certificate or the team), or `None`. Blocking.
pub fn vouched(path: &Path) -> Option<String> {
    const BUNDLES: [&str; 7] = ["app", "framework", "bundle", "plugin", "xpc", "appex", "kext"];
    let owner = path.ancestors().find(|dir| dir.extension().and_then(|e| e.to_str()).is_some_and(|e| BUNDLES.contains(&e))).unwrap_or(path);
    let sig = check(owner);
    if sig.status != "signed" || (!sig.apple && sig.team_id.is_empty()) {
        return None;
    }
    let target = owner.display().to_string();
    run("/usr/bin/codesign", &["--verify", "--strict", &target], Duration::from_secs(20)).ok().filter(|out| out.ok)?;
    Some(if sig.apple { "Apple".into() } else if sig.authority.is_empty() { sig.team_id } else { sig.authority })
}

/// The signature of a program or app bundle (`codesign`, fast). Blocking.
pub fn check(path: &Path) -> Signature {
    let when = stamp(path);
    if let Some(sig) = cached(cache(), path, when) {
        return sig;
    }
    let sig = read(path);
    store(cache(), path, when, &sig);
    sig
}

/// Whether Apple notarized a program or app (or it is Apple's own or from the App Store), as
/// Gatekeeper assesses it locally (`spctl`, a stapled or cached ticket; it does not wait on the
/// network). Of a file inside an app, the app's. `Some(false)` for unsigned and ad-hoc code,
/// `None` when it could not be told. Cached like [`check`]. Blocking.
pub fn notarized(path: &Path) -> Option<bool> {
    static CACHE: OnceLock<Cache<Option<bool>>> = OnceLock::new();
    let cache = CACHE.get_or_init(Default::default);
    let owner = path.ancestors().find(|dir| dir.extension().is_some_and(|e| e == "app")).unwrap_or(path);
    let when = stamp(owner);
    if let Some(answer) = cached(cache, owner, when) {
        return answer;
    }
    let sig = check(owner);
    let answer = if !cfg!(target_os = "macos") || !owner.exists() {
        None
    } else if sig.apple {
        Some(true)
    } else if sig.unsigned() {
        Some(false)
    } else {
        // An app is assessed as one to run; a bare program as one to install (to run, spctl
        // rejects anything that is not an app).
        let kind = if owner.extension().is_some_and(|e| e == "app") { "exec" } else { "install" };
        let target = owner.display().to_string();
        run("/usr/sbin/spctl", &["--assess", "-vv", "--type", kind, &target], Duration::from_secs(10)).ok().and_then(|out| {
            let text = format!("{}{}", out.stdout, out.stderr);
            let source = text.lines().find_map(|l| l.strip_prefix("source=")).unwrap_or("").trim().to_owned();
            if out.ok && (source.starts_with("Notarized") || source.contains("Apple") || source.contains("App Store")) {
                Some(true)
            } else if text.contains(": rejected") || source.starts_with("Unnotarized") || out.ok {
                Some(false)
            } else {
                None
            }
        })
    };
    store(cache, owner, when, &answer);
    answer
}


fn read(path: &Path) -> Signature {
    let mut sig = Signature { status: "unknown".into(), ..Default::default() };
    if !cfg!(target_os = "macos") || !path.exists() {
        return sig;
    }
    let path_text = path.display().to_string();
    let Ok(out) =
        run("/usr/bin/codesign", &["-dvvvv", "--entitlements", "-", "--xml", &path_text], Duration::from_secs(15))
    else {
        return sig;
    };
    let text = &out.stderr;
    if text.contains("not signed at all") {
        sig.status = "unsigned".into();
        return sig;
    }
    let field = |key: &str| text.lines().find_map(|l| l.strip_prefix(key)).map(|v| v.trim().to_owned()).unwrap_or_default();
    sig.team_id = Some(field("TeamIdentifier=")).filter(|t| t != "not set").unwrap_or_default();
    sig.identifier = field("Identifier=");
    sig.authority = field("Authority=");
    sig.apple = text.contains("Platform identifier=") || sig.authority.ends_with("Software Signing");
    sig.hardened_runtime = text.lines().any(|l| l.starts_with("CodeDirectory") && l.contains("runtime"));
    sig.status = if text.contains("Signature=adhoc") {
        "adhoc".into()
    } else if out.ok {
        "signed".into()
    } else {
        "unknown".into()
    };
    if let Ok(plist::Value::Dictionary(dict)) = plist::Value::from_reader_xml(out.stdout.as_bytes()) {
        sig.risky = RISKY
            .iter()
            .filter(|key| dict.get(**key).and_then(|v| v.as_boolean()) == Some(true))
            .map(|key| key.trim_start_matches("com.apple.security.").to_owned())
            .collect();
    }
    sig
}

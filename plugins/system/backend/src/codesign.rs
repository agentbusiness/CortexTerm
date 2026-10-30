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
    /// Whether Gatekeeper accepts it as notarized or from the App Store; `None` until
    /// [`assess`] ran.
    pub notarized: Option<bool>,
}

impl Signature {
    /// Not properly signed (unsigned or ad-hoc).
    pub fn unsigned(&self) -> bool {
        self.status == "unsigned" || self.status == "adhoc"
    }
}

type Cache = Mutex<HashMap<PathBuf, (Option<SystemTime>, Signature)>>;

fn cache() -> &'static Cache {
    static CACHE: OnceLock<Cache> = OnceLock::new();
    CACHE.get_or_init(Default::default)
}

fn cached(path: &Path, mtime: Option<SystemTime>) -> Option<Signature> {
    let cache = cache().lock().ok()?;
    let (when, sig) = cache.get(path)?;
    (*when == mtime).then(|| sig.clone())
}

fn store(path: &Path, mtime: Option<SystemTime>, sig: &Signature) {
    if let Ok(mut cache) = cache().lock() {
        cache.insert(path.to_path_buf(), (mtime, sig.clone()));
    }
}

fn mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The signature of a program or app bundle (`codesign`, fast). Blocking.
pub fn check(path: &Path) -> Signature {
    let when = mtime(path);
    if let Some(sig) = cached(path, when) {
        return sig;
    }
    let sig = read(path);
    store(path, when, &sig);
    sig
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

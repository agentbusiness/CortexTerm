//! The lookup keys the person saves (VirusTotal, abuse.ch), kept in the macOS Keychain: generic
//! passwords of the service [`SERVICE`] whose accounts are the key names. `ABUSE_CH_KEY` in the
//! environment overrides the saved abuse.ch key. A key file an older version read
//! (`<data>/keys/<name>`) is moved into the Keychain once at start and deleted; off macOS the keys
//! stay in those files. The values never leave this plugin: `system.keys.status` says only which
//! are set.

use cc_protocol::contracts::system::KeysStatus;

pub const SERVICE: &str = "CortexTerm security keys";
/// The keys, as the Keychain accounts and `system.keys.set` name them.
pub const NAMES: [&str; 2] = ["virustotal", "abusech"];

fn env_name(name: &str) -> Option<&'static str> {
    (name == "abusech").then_some("ABUSE_CH_KEY")
}

/// A key to use now: the environment variable, else the Keychain.
pub fn get(name: &str) -> Option<String> {
    env_name(name)
        .and_then(|var| std::env::var(var).ok())
        .or_else(|| keychain::get(name))
        .map(|key| key.trim().to_owned())
        .filter(|key| !key.is_empty())
}

/// Save a key; an empty value removes it.
pub fn set(name: &str, value: &str) -> Result<(), String> {
    if !NAMES.contains(&name) {
        return Err(format!("`{name}` is not a key this plugin keeps ({})", NAMES.join(", ")));
    }
    let value = value.trim();
    if value.is_empty() { keychain::delete(name) } else { keychain::set(name, value) }
}

/// Which keys are set (saved or in the environment), without reading a value.
pub fn status() -> KeysStatus {
    let set = |name: &str| env_name(name).and_then(|var| std::env::var(var).ok()).is_some_and(|v| !v.trim().is_empty()) || keychain::exists(name);
    KeysStatus { virustotal: set("virustotal"), abusech: set("abusech") }
}

/// Move key files an older version read into the Keychain (once: the file is deleted after).
#[cfg(target_os = "macos")]
pub fn import_files() {
    let dir = crate::util::data_dir().join("keys");
    for name in NAMES {
        let file = dir.join(name);
        let Ok(text) = std::fs::read_to_string(&file) else { continue };
        let value = text.trim();
        let moved = value.is_empty() || keychain::set(name, value).is_ok() && keychain::get(name).as_deref() == Some(value);
        if moved {
            let _ = std::fs::remove_file(&file);
        } else {
            tracing::warn!(key = name, "cannot move the key into the Keychain; the file stays");
        }
    }
    let _ = std::fs::remove_dir(&dir);
}

#[cfg(not(target_os = "macos"))]
pub fn import_files() {}

#[cfg(target_os = "macos")]
mod keychain {
    use super::SERVICE;

    pub fn get(name: &str) -> Option<String> {
        crate::keychain::get(SERVICE, name).ok().flatten()
    }

    /// Whether the item is there (its attributes only).
    pub fn exists(name: &str) -> bool {
        crate::keychain::exists(SERVICE, name)
    }

    pub fn set(name: &str, value: &str) -> Result<(), String> {
        crate::keychain::set(SERVICE, name, value)
    }

    pub fn delete(name: &str) -> Result<(), String> {
        crate::keychain::delete(SERVICE, name)
    }
}

/// Elsewhere there is no Keychain: the keys stay in `<data>/keys/<name>`, readable by the owner.
#[cfg(not(target_os = "macos"))]
mod keychain {
    fn file(name: &str) -> std::path::PathBuf {
        crate::util::data_dir().join("keys").join(name)
    }
    pub fn get(name: &str) -> Option<String> {
        std::fs::read_to_string(file(name)).ok()
    }
    pub fn exists(name: &str) -> bool {
        get(name).is_some_and(|key| !key.trim().is_empty())
    }
    pub fn set(name: &str, value: &str) -> Result<(), String> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = file(name);
        let _ = std::fs::create_dir_all(path.parent().unwrap_or(&path));
        std::fs::OpenOptions::new().create(true).truncate(true).write(true).mode(0o600).open(&path).and_then(|mut out| out.write_all(value.as_bytes())).map_err(|e| format!("{}: {e}", path.display()))
    }
    pub fn delete(name: &str) -> Result<(), String> {
        match std::fs::remove_file(file(name)) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error.to_string()),
            _ => Ok(()),
        }
    }
}

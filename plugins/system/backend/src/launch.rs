//! Launch agents and daemons: the folders programs use to start at login or boot, and what one
//! plist starts (its program, that program's signature and quarantine flag).

use crate::host;
use crate::util::{home, tilde};
use std::path::{Path, PathBuf};

/// `CORTEX_SYSTEM_LAUNCH_DIRS` (colon-separated) replaces them, so the watcher can be tried on a
/// scratch folder.
pub fn folders() -> Vec<PathBuf> {
    if let Ok(dirs) = std::env::var("CORTEX_SYSTEM_LAUNCH_DIRS") {
        return dirs.split(':').filter(|d| !d.is_empty()).map(PathBuf::from).collect();
    }
    if !cfg!(target_os = "macos") {
        return Vec::new();
    }
    vec![home().join("Library/LaunchAgents"), PathBuf::from("/Library/LaunchAgents"), PathBuf::from("/Library/LaunchDaemons")]
}

pub struct Item {
    pub plist: PathBuf,
    pub label: String,
    /// The program it starts (empty when the plist names none we can resolve).
    pub program: String,
    /// signed | adhoc | unsigned | unknown | missing
    pub signature: String,
    pub team: String,
    pub quarantined: bool,
}

impl Item {
    /// "launch agent" or "launch daemon".
    pub fn what(&self) -> &'static str {
        if self.plist.display().to_string().contains("LaunchDaemons") { "launch daemon" } else { "launch agent" }
    }

    pub fn folder(&self) -> String {
        self.plist.parent().map(tilde).unwrap_or_default()
    }

    /// Not properly signed (unsigned or ad-hoc).
    pub fn unsigned(&self) -> bool {
        self.signature == "unsigned" || self.signature == "adhoc"
    }

    /// "which is not signed", "which is signed (team ABCD1234)", ...
    pub fn verdict(&self) -> String {
        let mut text = match self.signature.as_str() {
            "missing" => "which does not exist".to_owned(),
            "unsigned" => "which is not signed".to_owned(),
            "adhoc" => "which is only ad-hoc signed".to_owned(),
            "signed" if !self.team.is_empty() => format!("which is signed (team {})", self.team),
            "signed" => "which is signed".to_owned(),
            _ => "whose signature could not be checked".to_owned(),
        };
        if self.quarantined {
            text.push_str(" and is still quarantined as downloaded and never opened");
        }
        text
    }
}

/// Read one plist (blocking: may run `codesign`).
pub fn inspect(plist: &Path) -> Option<Item> {
    let value = plist::Value::from_file(plist).ok()?;
    let dict = value.as_dictionary()?;
    let label = dict
        .get("Label")
        .and_then(|v| v.as_string())
        .map(str::to_owned)
        .unwrap_or_else(|| plist.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default());
    let program = dict
        .get("Program")
        .and_then(|v| v.as_string())
        .or_else(|| dict.get("ProgramArguments").and_then(|v| v.as_array()).and_then(|a| a.first()).and_then(|v| v.as_string()))
        .unwrap_or("")
        .to_owned();
    let program = match program.strip_prefix("~/") {
        Some(rest) => home().join(rest).display().to_string(),
        None => program,
    };
    let path = Path::new(&program);
    let (signature, team) = if !program.starts_with('/') {
        ("unknown".to_owned(), String::new())
    } else if !path.exists() {
        ("missing".to_owned(), String::new())
    } else {
        host::signature(path)
    };
    let quarantined = path.exists() && host::quarantined(path);
    Some(Item { plist: plist.to_path_buf(), label, program, signature, team, quarantined })
}

/// Every plist in the launch folders.
pub fn all() -> Vec<Item> {
    folders()
        .iter()
        .filter_map(|dir| std::fs::read_dir(dir).ok())
        .flat_map(|entries| entries.flatten().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "plist"))
        .filter_map(|p| inspect(&p))
        .collect()
}

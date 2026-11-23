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
    /// Signed by Apple (only looked at for a `com.apple.` label).
    pub apple: bool,
    /// What its `EnvironmentVariables` put in `DYLD_INSERT_LIBRARIES` (empty when nothing).
    pub inserts: String,
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

    /// A Homebrew service (`brew services`): a formula's own program, started from Homebrew's
    /// folders. Homebrew builds them on this Mac, so they are only ad-hoc signed.
    pub fn homebrew(&self) -> bool {
        let file = self.plist.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        (self.label.starts_with("homebrew.mxcl.") || file.starts_with("homebrew.mxcl."))
            && ["/opt/homebrew/", "/usr/local/Cellar/", "/usr/local/opt/", "/home/linuxbrew/.linuxbrew/"].iter().any(|p| self.program.starts_with(p))
    }

    /// Why this item is a clear sign of an intruder, when it is one: it wears Apple's name
    /// without Apple's signature, it injects a library into what it starts, or it starts an
    /// unsigned program from a temporary or shared folder or from inside ~/Library.
    pub fn danger(&self) -> Option<String> {
        if self.label.starts_with("com.apple.") && self.program.starts_with('/') && !self.apple {
            return Some(format!("its label {} claims to be Apple's but {} is not signed by Apple", self.label, self.program));
        }
        if !self.inserts.is_empty() {
            return Some(format!("it sets DYLD_INSERT_LIBRARIES={}, which injects code into the program it starts", self.inserts));
        }
        let library = home().join("Library").display().to_string();
        let odd = ["/tmp/", "/private/tmp/", "/private/var/tmp/", "/Users/Shared/"].iter().any(|p| self.program.starts_with(p))
            || (self.program.starts_with(&format!("{library}/")) && !self.program.starts_with(&format!("{library}/Application Support/")));
        if odd && self.unsigned() {
            return Some(format!("it starts {}, an unsigned program in a temporary, shared or hidden library folder", self.program));
        }
        None
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
    let apple = label.starts_with("com.apple.") && path.exists() && crate::codesign::check(path).apple;
    let inserts = dict
        .get("EnvironmentVariables")
        .and_then(|v| v.as_dictionary())
        .and_then(|env| env.get("DYLD_INSERT_LIBRARIES"))
        .and_then(|v| v.as_string())
        .unwrap_or("")
        .to_owned();
    Some(Item { plist: plist.to_path_buf(), label, program, signature, team, quarantined, apple, inserts })
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

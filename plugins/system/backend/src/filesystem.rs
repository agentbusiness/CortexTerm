//! Home first, then every reachable directory, including mounted volumes and symlink targets.
//! No project-name, depth or count cutoff. Device/pseudo filesystems are not file scan targets.

use crate::sweep::Part;
use crate::util::{home, tilde};
use std::collections::{BTreeSet, HashSet};
use std::fs::{Metadata, ReadDir};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

pub struct Walk {
    roots: Vec<PathBuf>,
    stack: Vec<(PathBuf, ReadDir)>,
    cancelled: Arc<AtomicBool>,
    seen: HashSet<(u64, u64)>,
    pub skipped: Vec<String>,
}

impl Walk {
    pub fn new() -> Self {
        Self {
            roots: vec![PathBuf::from("/"), home()],
            stack: Vec::new(),
            cancelled: Arc::new(AtomicBool::new(false)),
            seen: HashSet::new(),
            skipped: Vec::new(),
        }
    }

    pub fn for_scan(scan: &Shared) -> Self {
        Self {
            cancelled: scan.cancelled.clone(),
            ..Self::new()
        }
    }

    fn enter(&mut self, path: &Path, meta: &Metadata) {
        match std::fs::read_dir(path) {
            Ok(read) => {
                self.seen.insert((meta.dev(), meta.ino()));
                self.stack.push((path.to_path_buf(), read));
            }
            Err(error) => self
                .skipped
                .push(format!("filesystem: {}: {error}", tilde(path))),
        }
    }

    /// Exclude a check's own records/rules without depending on the spelling of a symlink.
    pub fn exclude(&mut self, path: &Path) {
        if let Ok(meta) = std::fs::metadata(path) {
            self.seen.insert((meta.dev(), meta.ino()));
        }
    }
}

impl Iterator for Walk {
    type Item = (PathBuf, Metadata);

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.cancelled.load(Ordering::Relaxed) {
                self.skipped
                    .push("filesystem: scan cancelled before traversal completed".into());
                return None;
            }
            let path = if let Some((dir, read)) = self.stack.last_mut() {
                match read.next() {
                    Some(Ok(entry)) => entry.path(),
                    Some(Err(error)) => {
                        self.skipped.push(format!(
                            "filesystem directory entry in {}: {error}",
                            tilde(dir)
                        ));
                        continue;
                    }
                    None => {
                        self.stack.pop();
                        continue;
                    }
                }
            } else {
                self.roots.pop()?
            };
            // Do not open devices, process pseudo-files, or their aliases.
            let canonical = match path.canonicalize() {
                Ok(path) => path,
                Err(error) => {
                    self.skipped
                        .push(format!("filesystem: {}: {error}", tilde(&path)));
                    continue;
                }
            };
            if ["/dev", "/proc", "/sys"]
                .iter()
                .any(|p| canonical.starts_with(p))
            {
                continue;
            }
            let meta = match std::fs::metadata(&path) {
                Ok(meta) => meta,
                Err(error) => {
                    self.skipped
                        .push(format!("filesystem: {}: {error}", tilde(&path)));
                    continue;
                }
            };
            if meta.is_dir() {
                if self.seen.contains(&(meta.dev(), meta.ino())) {
                    continue;
                }
                self.enter(&path, &meta);
            }
            return Some((path, meta));
        }
    }
}

#[derive(Default)]
pub struct Discovery {
    pub projects: BTreeSet<PathBuf>,
    pub apps: BTreeSet<PathBuf>,
    pub agent_configs: BTreeSet<PathBuf>,
    pub instructions: BTreeSet<PathBuf>,
    pub skills: BTreeSet<PathBuf>,
    pub skipped: Vec<String>,
}

/// One discovery walk shared by the areas of a sweep, not a persistent/stale cache.
pub type Shared = Arc<Scan>;

#[derive(Default)]
pub struct Scan {
    found: OnceLock<Discovery>,
    cancelled: Arc<AtomicBool>,
}

impl Scan {
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Relaxed)
    }

    pub fn get(&self) -> &Discovery {
        self.found.get_or_init(|| {
            Discovery::scan_with(Walk {
                cancelled: self.cancelled.clone(),
                ..Walk::new()
            })
        })
    }
}

/// Timed-out chat checks must not leave whole-disk blocking workers running indefinitely.
pub struct CancelOnDrop(pub Shared);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.cancelled.store(true, Ordering::Relaxed);
    }
}

impl Discovery {
    pub fn scan() -> Self {
        Self::scan_with(Walk::new())
    }

    fn scan_with(mut walk: Walk) -> Self {
        let mut found = Self::default();
        for (path, meta) in walk.by_ref() {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if meta.is_dir() && name.ends_with(".app") {
                found.apps.insert(path.clone());
            }
            if meta.is_file() {
                if [
                    ".claude.json",
                    ".claude/settings.json",
                    ".claude/settings.local.json",
                    "Claude/claude_desktop_config.json",
                    ".cursor/mcp.json",
                    ".codeium/windsurf/mcp_config.json",
                    "Code/User/mcp.json",
                    "Code/User/settings.json",
                    "Cursor/User/settings.json",
                    ".gemini/settings.json",
                    ".codex/config.toml",
                    ".mcp.json",
                    ".vscode/mcp.json",
                ]
                .iter()
                .any(|suffix| path.ends_with(suffix))
                {
                    found.agent_configs.insert(path.clone());
                }
                if matches!(
                    name,
                    "AGENTS.md"
                        | "CLAUDE.md"
                        | "CLAUDE.local.md"
                        | "GEMINI.md"
                        | ".cursorrules"
                        | ".windsurfrules"
                        | "copilot-instructions.md"
                ) || (path.extension().is_some_and(|e| e == "md" || e == "mdc")
                    && path.parent().is_some_and(|p| p.ends_with(".cursor/rules")))
                {
                    found.instructions.insert(path.clone());
                }
                if path.extension().is_some_and(|e| e == "md" || e == "mdc")
                    && (name == "SKILL.md"
                        || path
                            .components()
                            .any(|p| p.as_os_str() == "skills" || p.as_os_str() == ".clawhub")
                        || path.ancestors().any(|p| p.ends_with(".claude/plugins")))
                {
                    found.skills.insert(path.clone());
                }
            }
            if matches!(
                name,
                ".git"
                    | ".claude"
                    | ".codex"
                    | ".cursor"
                    | ".vscode"
                    | ".gemini"
                    | ".github"
                    | "AGENTS.md"
                    | "CLAUDE.md"
                    | "GEMINI.md"
                    | ".mcp.json"
                    | "pyvenv.cfg"
                    | "package-lock.json"
                    | "npm-shrinkwrap.json"
                    | "pnpm-lock.yaml"
                    | "Cargo.lock"
                    | "poetry.lock"
                    | "uv.lock"
                    | "Gemfile.lock"
                    | "go.mod"
            ) || name.starts_with(".env")
                || (name.starts_with("requirements") && name.ends_with(".txt"))
            {
                if let Some(parent) = path.parent() {
                    found.projects.insert(parent.to_path_buf());
                }
            }
        }
        found.skipped = walk.skipped;
        found
    }

    pub fn report(&self, part: &mut Part) {
        part.checked.push("filesystem discovery: home first, then /, other users, system folders and mounted volumes; directory aliases visited once".into());
        part.skipped.extend(self.skipped.iter().cloned());
        part.skipped.push("filesystem: device and process pseudo-filesystems (/dev, /proc, /sys) are not regular file scan targets".into());
    }
}

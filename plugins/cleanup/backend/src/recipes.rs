//! The recipes (`data/recipes.toml`): what the scan knows, read from the live folder when there
//! is one, else from the package. Two more are the plugin's own: `cachedir-tag` (any folder with
//! a CACHEDIR.TAG, the cache directory standard) and `stale-folder` (a big folder untouched for
//! months), plus `duplicate` for large files kept twice.

use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct Recipe {
    pub id: String,
    pub title: String,
    pub kind: String,
    pub safety: String,
    pub why: String,
    pub regenerate: String,
    pub command: String,
    pub names: Vec<String>,
    pub beside: Vec<String>,
    pub inside: Vec<String>,
    pub paths: Vec<String>,
    pub each: bool,
    pub programs: Vec<String>,
    pub apps: Vec<String>,
    pub locks: Vec<String>,
    pub stale: String,
    pub ignored: bool,
    pub min_age_days: u64,
    pub min_mb: Option<u64>,
    pub xcode: bool,
    pub worktree: bool,
    /// The command cleans through the program that uses the place (Docker), so its open files
    /// do not stop it.
    pub open_ok: bool,
}

impl Recipe {
    pub fn min_bytes(&self) -> u64 {
        self.min_mb.unwrap_or(20) * 1024 * 1024
    }

    /// `name` (the folder's own) with `parent` (its parent's name) matches one of `names`.
    pub fn matches_name(&self, name: &str, parent: &str) -> bool {
        self.names.iter().any(|entry| match entry.split_once('/') {
            Some((up, own)) => own == name && up == parent,
            None => entry == name,
        })
    }

    /// The project folder of a folder found by name.
    pub fn project_of(&self, folder: &Path) -> Option<PathBuf> {
        let nested = self.names.iter().any(|entry| entry.contains('/'));
        let parent = folder.parent()?;
        if nested { parent.parent().map(Path::to_path_buf) } else { Some(parent.to_path_buf()) }
    }

    /// The project holds one of `beside` (or there is no such condition).
    pub fn beside_ok(&self, project: &Path) -> bool {
        if self.beside.is_empty() {
            return true;
        }
        self.beside.iter().any(|marker| match marker.strip_prefix('*') {
            Some(suffix) => std::fs::read_dir(project)
                .map(|entries| entries.flatten().any(|entry| entry.file_name().to_string_lossy().ends_with(suffix)))
                .unwrap_or(false),
            None => project.join(marker).exists(),
        })
    }

    pub fn inside_ok(&self, folder: &Path) -> bool {
        self.inside.is_empty() || self.inside.iter().any(|name| folder.join(name).exists())
    }
}

#[derive(Deserialize)]
struct File {
    #[serde(default)]
    recipe: Vec<Recipe>,
}

/// The plugin's `data` folder: the live copy when the frame names one, else the packaged one.
fn data_dir() -> Option<PathBuf> {
    if let Some(live) = std::env::var_os("CORTEX_PLUGIN_LIVE").filter(|v| !v.is_empty()).map(PathBuf::from) {
        let dir = live.join("data");
        if dir.join("recipes.toml").is_file() {
            return Some(dir);
        }
    }
    let exe = std::env::current_exe().ok()?;
    exe.parent()?.ancestors().take(6).map(|dir| dir.join("data")).find(|dir| dir.join("recipes.toml").is_file())
}

/// Read on every scan, so an edit in the live folder counts from the next one.
pub fn load() -> Result<Vec<Recipe>, String> {
    let dir = data_dir().ok_or("data/recipes.toml was not found")?;
    let text = std::fs::read_to_string(dir.join("recipes.toml")).map_err(|e| format!("data/recipes.toml: {e}"))?;
    let file: File = toml::from_str(&text).map_err(|e| format!("data/recipes.toml: {e}"))?;
    Ok(file.recipe.into_iter().filter(|r| !r.id.is_empty()).collect())
}

/// `~`, `$TMPDIR` (its real path: `/private/var/folders/…` on macOS, as the walk meets it) and
/// `$UID` expanded.
pub fn expand(path: &str, home: &Path) -> PathBuf {
    let uid = unsafe { libc::getuid() }.to_string();
    let tmp = std::env::var("TMPDIR").unwrap_or_else(|_| "/tmp".into());
    let tmp = std::fs::canonicalize(&tmp).map(|p| p.to_string_lossy().into_owned()).unwrap_or(tmp);
    let path = path.replace("$UID", &uid).replace("$TMPDIR", tmp.trim_end_matches('/'));
    match path.strip_prefix('~') {
        Some(rest) => home.join(rest.trim_start_matches('/')),
        None => PathBuf::from(path),
    }
}

/// The places a `paths` entry names: itself, or (last component `*` / `*.ext`) its matching entries.
pub fn places(entry: &str, home: &Path) -> Vec<PathBuf> {
    let path = expand(entry, home);
    let last = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let Some(suffix) = last.strip_prefix('*') else {
        return if path.symlink_metadata().is_ok() { vec![path] } else { Vec::new() };
    };
    let Some(parent) = path.parent() else { return Vec::new() };
    // `/private/tmp/claude-$UID/*`: a `*` inside an earlier component is not supported; the
    // parent is taken as written.
    std::fs::read_dir(parent)
        .map(|entries| {
            entries
                .flatten()
                .filter(|entry| entry.file_name().to_string_lossy().ends_with(suffix))
                .filter(|entry| entry.file_type().map(|t| !t.is_symlink()).unwrap_or(false))
                .map(|entry| entry.path())
                .collect()
        })
        .unwrap_or_default()
}

/// A fixed place's root (`~/Library/Caches/JetBrains` for `~/Library/Caches/JetBrains/*`): the
/// walk leaves these to the recipe.
pub fn root_of(entry: &str, home: &Path) -> PathBuf {
    let path = expand(entry, home);
    if path.file_name().is_some_and(|n| n.to_string_lossy().starts_with('*')) {
        path.parent().map(Path::to_path_buf).unwrap_or(path)
    } else {
        path
    }
}

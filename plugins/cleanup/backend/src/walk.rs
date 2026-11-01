//! The parallel walk. Sizes are bytes on disk (allocated blocks), a hard-linked file counted once,
//! symbolic links never followed, and the walk stays on the home folder's volume. A folder a
//! recipe recognises is measured whole and not looked into further; a folder the person keeps is
//! not read at all, which is what makes "keep" save scanning time.

use crate::recipes::Recipe;
use rayon::prelude::*;
use std::collections::HashSet;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

/// Files from this size take part in the duplicate search.
pub const BIG_FILE: u64 = 64 * 1024 * 1024;
/// A folder untouched this long, and this big, is offered as stale.
pub const STALE_DAYS: u64 = 180;
pub const STALE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Debug, Clone, Copy, Default)]
pub struct Agg {
    pub bytes: u64,
    pub files: u64,
    pub newest_ms: u64,
    /// A recipe's item is somewhere below.
    pub has_item: bool,
}

impl Agg {
    fn add(&mut self, other: Agg) {
        self.bytes += other.bytes;
        self.files += other.files;
        self.newest_ms = self.newest_ms.max(other.newest_ms);
        self.has_item |= other.has_item;
    }
}

#[derive(Debug, Clone)]
pub struct Big {
    pub path: PathBuf,
    pub len: u64,
    pub dev: u64,
    pub ino: u64,
    pub mtime_ms: u64,
}

/// A recipe's find, before the checks.
#[derive(Debug, Clone)]
pub struct Raw {
    pub path: PathBuf,
    /// Index into the recipes, or None for a folder with a CACHEDIR.TAG.
    pub recipe: Option<usize>,
    pub project: Option<PathBuf>,
    pub agg: Agg,
}

#[derive(Default)]
pub struct Counters {
    pub files: AtomicU64,
    pub bytes: AtomicU64,
    pub stop: AtomicBool,
    pub folder: Mutex<String>,
}

pub struct Walk<'a> {
    pub home: &'a Path,
    pub dev: u64,
    pub recipes: &'a [Recipe],
    /// Not read at all: kept and postponed items, and the recipes' fixed places.
    pub skip: &'a HashSet<PathBuf>,
    pub counters: &'a Counters,
    links: Mutex<HashSet<(u64, u64)>>,
    pub found: Mutex<Vec<Raw>>,
    pub big: Mutex<Vec<Big>>,
    pub stale: Mutex<Vec<(PathBuf, Agg)>>,
}

fn mtime_ms(meta: &std::fs::Metadata) -> u64 {
    (meta.mtime().max(0) as u64) * 1000 + (meta.mtime_nsec().max(0) as u64) / 1_000_000
}

pub fn now_ms() -> u64 {
    cc_protocol::contracts::now_ms()
}

/// Folders the walk never enters: other apps' libraries and the repositories' own history.
fn private_folder(name: &str) -> bool {
    name == ".git"
        || [".photoslibrary", ".musiclibrary", ".tvlibrary", ".app", ".fcpbundle", ".band", ".logicx"].iter().any(|s| name.ends_with(s))
}

impl<'a> Walk<'a> {
    pub fn new(home: &'a Path, recipes: &'a [Recipe], skip: &'a HashSet<PathBuf>, counters: &'a Counters) -> Self {
        let dev = std::fs::metadata(home).map(|m| m.dev()).unwrap_or(0);
        Self {
            home,
            dev,
            recipes,
            skip,
            counters,
            links: Mutex::new(HashSet::new()),
            found: Mutex::new(Vec::new()),
            big: Mutex::new(Vec::new()),
            stale: Mutex::new(Vec::new()),
        }
    }

    /// One folder and everything below. `depth` is the folder's depth below home (home is 0);
    /// `measure` only counts (inside an item), `big` collects large files for the duplicates.
    pub fn walk(&self, dir: &Path, depth: usize, measure: bool, big: bool) -> Agg {
        let mut agg = Agg::default();
        if self.counters.stop.load(Ordering::Relaxed) {
            return agg;
        }
        if let Ok(mut folder) = self.counters.folder.try_lock() {
            *folder = dir.strip_prefix(self.home).map(|p| format!("~/{}", p.display())).unwrap_or_else(|_| dir.display().to_string());
        }
        let Ok(entries) = std::fs::read_dir(dir) else { return agg };
        let mut folders = Vec::new();
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else { continue };
            if kind.is_symlink() {
                continue;
            }
            if kind.is_dir() {
                folders.push(entry.path());
                continue;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.nlink() > 1 && !self.links.lock().unwrap_or_else(|e| e.into_inner()).insert((meta.dev(), meta.ino())) {
                continue;
            }
            let bytes = meta.blocks() * 512;
            agg.bytes += bytes;
            agg.files += 1;
            agg.newest_ms = agg.newest_ms.max(mtime_ms(&meta));
            self.counters.files.fetch_add(1, Ordering::Relaxed);
            self.counters.bytes.fetch_add(bytes, Ordering::Relaxed);
            if big && meta.len() >= BIG_FILE && kind.is_file() {
                self.big.lock().unwrap_or_else(|e| e.into_inner()).push(Big {
                    path: entry.path(),
                    len: meta.len(),
                    dev: meta.dev(),
                    ino: meta.ino(),
                    mtime_ms: mtime_ms(&meta),
                });
            }
        }
        let parent = dir.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let sub: Vec<Agg> = folders.par_iter().map(|folder| self.folder(folder, &parent, depth + 1, measure, big)).collect();
        for child in sub {
            agg.add(child);
        }
        agg
    }

    fn folder(&self, folder: &Path, parent: &str, depth: usize, measure: bool, big: bool) -> Agg {
        let Ok(meta) = std::fs::symlink_metadata(folder) else { return Agg::default() };
        if meta.dev() != self.dev {
            return Agg::default();
        }
        if measure {
            return self.walk(folder, depth, true, big);
        }
        let name = folder.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if self.skip.contains(folder) || private_folder(&name) || (depth == 1 && name == "Library") {
            return Agg::default();
        }
        if let Some(found) = self.recognise(folder, &name, parent) {
            return found;
        }
        let agg = self.walk(folder, depth, false, big);
        let old = now_ms().saturating_sub(STALE_DAYS * 86_400_000);
        if (2..=4).contains(&depth) && !agg.has_item && agg.bytes >= STALE_BYTES && agg.newest_ms > 0 && agg.newest_ms < old {
            self.stale.lock().unwrap_or_else(|e| e.into_inner()).push((folder.to_path_buf(), agg));
        }
        agg
    }

    /// A folder a recipe (or a CACHEDIR.TAG) names: measured and recorded, `None` otherwise.
    fn recognise(&self, folder: &Path, name: &str, parent: &str) -> Option<Agg> {
        for (index, recipe) in self.recipes.iter().enumerate() {
            if recipe.names.is_empty() || !recipe.matches_name(name, parent) || !recipe.inside_ok(folder) {
                continue;
            }
            let Some(project) = recipe.project_of(folder) else { continue };
            if !recipe.beside_ok(&project) || crate::git::tracked(folder) || (recipe.ignored && crate::git::ignored(folder) == Some(false)) {
                continue;
            }
            let targets: Vec<PathBuf> = if recipe.each {
                std::fs::read_dir(folder)
                    .map(|entries| entries.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_dir())).map(|e| e.path()).collect())
                    .unwrap_or_default()
            } else {
                vec![folder.to_path_buf()]
            };
            for target in targets {
                let agg = self.walk(&target, 0, true, recipe.kind == "model");
                self.found.lock().unwrap_or_else(|e| e.into_inner()).push(Raw { path: target, recipe: Some(index), project: Some(project.clone()), agg });
            }
            return Some(Agg { has_item: true, ..Agg::default() });
        }
        // A CACHEDIR.TAG marks a cache, unless it is a virtual environment (uv tags those) or holds
        // a recipe's fixed place (`~/.cargo/registry` is read by its own recipe).
        if folder.join("CACHEDIR.TAG").is_file() && !folder.join("pyvenv.cfg").exists() && !self.skip.iter().any(|s| s.starts_with(folder)) {
            let agg = self.walk(folder, 0, true, false);
            let project = folder.parent().map(Path::to_path_buf);
            self.found.lock().unwrap_or_else(|e| e.into_inner()).push(Raw { path: folder.to_path_buf(), recipe: None, project, agg });
            return Some(Agg { has_item: true, ..Agg::default() });
        }
        None
    }
}

/// Bytes on disk, files and newest change of one folder or file (no recipes, no skipping).
pub fn measure(path: &Path) -> Agg {
    let skip = HashSet::new();
    let counters = Counters::default();
    let home = path.parent().unwrap_or(path);
    let walk = Walk::new(home, &[], &skip, &counters);
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.is_dir() => {
            let mut walk = walk;
            walk.dev = meta.dev();
            walk.walk(path, 0, true, false)
        }
        Ok(meta) if !meta.file_type().is_symlink() => Agg { bytes: meta.blocks() * 512, files: 1, newest_ms: mtime_ms(&meta), has_item: false },
        _ => Agg::default(),
    }
}

/// Big files inside one place (the model recipes' folders take part in the duplicate search).
pub fn take_big(walk: &Walk) -> Vec<Big> {
    std::mem::take(&mut *walk.big.lock().unwrap_or_else(|e| e.into_inner()))
}

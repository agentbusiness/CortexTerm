//! One scan: the recipes' fixed places, the walk of the home folder, the duplicate search, then
//! the checks that make a find an [`Item`]: age and size, who uses it, git, and for a project
//! still worked on, only its older builds. Runs on a low-priority thread pool.

use crate::inuse::Snapshot;
use crate::recipes::{self, Recipe};
use crate::walk::{self, Agg, Counters, Raw, Walk};
use crate::{dupes, git, stale};
use cc_protocol::contracts::cleanup::{Item, Progress};
use std::collections::{HashMap, HashSet};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::atomic::Ordering;

const DAY_MS: u64 = 86_400_000;
/// A project changed or built within this is being worked on: only its older builds are offered.
const ACTIVE_DAYS: u64 = 14;
/// A whole item changed within this is warm: the AI leaves it alone, the person may still clean it.
const WARM_DAYS: u64 = 2;

#[derive(Default)]
pub struct Live {
    pub counters: Counters,
    pub phase: Mutex<&'static str>,
    pub found: std::sync::atomic::AtomicU32,
    pub found_bytes: std::sync::atomic::AtomicU64,
}

impl Live {
    pub fn progress(&self, scan: &str) -> Progress {
        Progress {
            scan: scan.to_owned(),
            phase: (*self.phase.lock().unwrap_or_else(|e| e.into_inner())).to_owned(),
            files: self.counters.files.load(Ordering::Relaxed),
            bytes: self.counters.bytes.load(Ordering::Relaxed),
            folder: self.counters.folder.lock().map(|f| f.clone()).unwrap_or_default(),
            found: self.found.load(Ordering::Relaxed),
            found_bytes: self.found_bytes.load(Ordering::Relaxed),
        }
    }

    fn phase(&self, phase: &'static str) {
        *self.phase.lock().unwrap_or_else(|e| e.into_inner()) = phase;
    }
}

/// What a scan needs from outside: folders the person keeps or postponed (not read), and when
/// CortexTerm last ran a command in each folder (from the graph's CommandRuns).
pub struct Input {
    pub home: PathBuf,
    pub skip: HashSet<PathBuf>,
    pub skip_ids: HashSet<String>,
    pub runs: HashMap<String, u64>,
}

pub struct Output {
    pub items: Vec<Item>,
    pub files: u64,
    pub bytes: u64,
    pub stopped: bool,
}

pub fn run(input: Input, live: &Live) -> Result<Output, String> {
    let recipes = recipes::load()?;
    let home = input.home.as_path();
    let mut skip = input.skip.clone();
    for recipe in &recipes {
        for entry in &recipe.paths {
            skip.insert(recipes::root_of(entry, home));
        }
    }
    for never in crate::clean::NEVER {
        skip.insert(recipes::expand(never, home));
    }
    let walker = Walk::new(home, &recipes, &skip, &live.counters);
    let mut raws: Vec<Raw> = Vec::new();

    live.phase("places");
    for (index, recipe) in recipes.iter().enumerate() {
        for entry in &recipe.paths {
            for place in recipes::places(entry, home) {
                if input.skip.contains(&place) || live.counters.stop.load(Ordering::Relaxed) {
                    continue;
                }
                let mut agg = match std::fs::symlink_metadata(&place) {
                    Ok(meta) if meta.is_dir() => {
                        let mut w = Walk::new(home, &[], &skip, &live.counters);
                        w.dev = meta.dev();
                        let agg = w.walk(&place, 0, true, recipe.kind == "model");
                        walker.big.lock().unwrap_or_else(|e| e.into_inner()).extend(walk::take_big(&w));
                        agg
                    }
                    _ => walk::measure(&place),
                };
                if recipe.kind == "trash" {
                    agg.newest_ms = 0;
                }
                let project = if recipe.xcode { xcode_project(&place) } else { None };
                raws.push(Raw { path: place, recipe: Some(index), project, agg });
            }
        }
    }

    live.phase("walk");
    walker.walk(home, 0, false, true);
    raws.extend(std::mem::take(&mut *walker.found.lock().unwrap_or_else(|e| e.into_inner())));

    live.phase("duplicates");
    let big = walk::take_big(&walker);
    let sets = dupes::find(big, &live.counters.stop);

    live.phase("checks");
    let snapshot = Snapshot::take();
    let now = walk::now_ms();
    let mut items: Vec<Item> = raws.iter().filter_map(|raw| item(raw, raw.recipe.map(|i| &recipes[i]), &snapshot, &input, now)).collect();

    // Stale folders: the shallowest of nested ones.
    let mut stale_dirs = std::mem::take(&mut *walker.stale.lock().unwrap_or_else(|e| e.into_inner()));
    stale_dirs.sort_by(|a, b| a.0.cmp(&b.0));
    let mut last: Option<PathBuf> = None;
    for (path, agg) in stale_dirs {
        if last.as_ref().is_some_and(|l| path.starts_with(l)) {
            continue;
        }
        last = Some(path.clone());
        items.push(stale_item(&path, agg, &snapshot, now));
    }

    // A find inside another one goes with it.
    items.sort_by(|a, b| a.path.cmp(&b.path));
    let mut kept: Vec<Item> = Vec::new();
    for item in items {
        if kept.last().is_some_and(|l| Path::new(&item.path).starts_with(&l.path)) {
            continue;
        }
        kept.push(item);
    }
    for set in sets {
        let id = format!("dupe:{}", &set.hash[..32.min(set.hash.len())]);
        if input.skip_ids.contains(&id) {
            continue;
        }
        kept.push(duplicate_item(id, set, &snapshot));
    }
    kept.retain(|item| item.id.len() <= 1000);
    for item in &kept {
        live.found.fetch_add(1, Ordering::Relaxed);
        live.found_bytes.fetch_add(item.bytes, Ordering::Relaxed);
    }
    Ok(Output {
        items: kept,
        files: live.counters.files.load(Ordering::Relaxed),
        bytes: live.counters.bytes.load(Ordering::Relaxed),
        stopped: live.counters.stop.load(Ordering::Relaxed),
    })
}

/// The newest change of a project's own files: its top-level files, git's index and log, and
/// the last command CortexTerm ran inside it.
pub fn project_active_ms(project: &Path, runs: &HashMap<String, u64>) -> u64 {
    let mtime = |p: &Path| std::fs::metadata(p).map(|m| (m.mtime().max(0) as u64) * 1000).unwrap_or(0);
    let files = std::fs::read_dir(project)
        .map(|entries| entries.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_file())).map(|e| mtime(&e.path())).max().unwrap_or(0))
        .unwrap_or(0);
    let git = mtime(&project.join(".git/index")).max(mtime(&project.join(".git/logs/HEAD")));
    let prefix = project.to_string_lossy();
    let ran = runs.iter().filter(|(folder, _)| folder.starts_with(prefix.as_ref())).map(|(_, at)| *at).max().unwrap_or(0);
    files.max(git).max(ran)
}

/// DerivedData's project: `WorkspacePath` in its info.plist (the folder holding it).
fn xcode_project(place: &Path) -> Option<PathBuf> {
    let value = plist::Value::from_file(place.join("info.plist")).ok()?;
    let workspace = value.as_dictionary()?.get("WorkspacePath")?.as_string()?;
    Path::new(workspace).parent().map(Path::to_path_buf)
}

fn item(raw: &Raw, recipe: Option<&Recipe>, snapshot: &Snapshot, input: &Input, now: u64) -> Option<Item> {
    let path = raw.path.to_string_lossy().into_owned();
    if input.skip_ids.contains(&path) {
        return None;
    }
    let (title, kind, safety, why, regenerate, id, min_bytes, min_age) = match recipe {
        Some(r) => (r.title.clone(), r.kind.clone(), r.safety.clone(), r.why.clone(), r.regenerate.clone(), r.id.clone(), r.min_bytes(), r.min_age_days),
        None => (
            "Cache folder".to_owned(),
            "cache".to_owned(),
            "regenerable".to_owned(),
            "Marked as a cache by the program that made it (CACHEDIR.TAG).".to_owned(),
            "the program makes it again".to_owned(),
            "cachedir-tag".to_owned(),
            20 * 1024 * 1024,
            0,
        ),
    };
    let mut agg: Agg = raw.agg;
    if agg.bytes < min_bytes || (min_age > 0 && agg.newest_ms + min_age * DAY_MS > now) {
        return None;
    }
    let project = raw.project.as_deref();
    let mut why = why;
    if recipe.is_some_and(|r| r.xcode) {
        match project {
            Some(p) if p.exists() => {}
            _ => why.push_str(" Its project is gone."),
        }
    }
    let active = project.map(|p| project_active_ms(p, &input.runs)).unwrap_or(0).max(agg.newest_ms) + ACTIVE_DAYS * DAY_MS > now;
    let mut scope = "whole";
    let mut users;
    if recipe.is_some_and(|r| r.stale == "cargo") && active {
        // Only what cargo will not use again: a running build's lock, or a file open in it, stops it.
        let parts = stale::cargo(&raw.path);
        agg = parts.iter().map(|p| walk::measure(p)).fold(Agg::default(), |mut sum, a| {
            sum.bytes += a.bytes;
            sum.files += a.files;
            sum.newest_ms = sum.newest_ms.max(a.newest_ms);
            sum
        });
        if agg.bytes < min_bytes {
            return None;
        }
        scope = "stale";
        why = format!("Older builds cargo will not use again ({} parts); the current build stays.", parts.len());
        users = snapshot.users(&raw.path, None, recipe);
    } else {
        users = snapshot.users(&raw.path, project, recipe);
    }
    if recipe.is_some_and(|r| r.worktree) {
        users.extend(git::worktree_work(&raw.path));
    }
    let state = if !users.is_empty() {
        "in_use"
    } else if scope == "whole" && kind != "trash" && agg.newest_ms + WARM_DAYS * DAY_MS > now {
        "warm"
    } else {
        "open"
    };
    let how = if kind == "trash" {
        "empty"
    } else if recipe.is_some_and(|r| !r.command.is_empty()) && scope == "whole" {
        "command"
    } else if safety == "review" {
        "trash"
    } else {
        "delete"
    };
    Some(Item {
        id: path.clone(),
        path,
        title,
        kind,
        recipe: id,
        bytes: agg.bytes,
        files: agg.files,
        newest_ms: agg.newest_ms,
        project: project.map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
        scope: scope.into(),
        safety,
        state: state.into(),
        in_use_by: users,
        why,
        regenerate,
        how: how.into(),
        copies: Vec::new(),
        decision: None,
    })
}

fn stale_item(path: &Path, agg: Agg, snapshot: &Snapshot, now: u64) -> Item {
    let months = (now.saturating_sub(agg.newest_ms) / (30 * DAY_MS)).max(1);
    let users = snapshot.users(path, None, None);
    Item {
        id: path.to_string_lossy().into_owned(),
        path: path.to_string_lossy().into_owned(),
        title: format!("Untouched for {months} months"),
        kind: "stale".into(),
        recipe: "stale-folder".into(),
        bytes: agg.bytes,
        files: agg.files,
        newest_ms: agg.newest_ms,
        project: String::new(),
        scope: "whole".into(),
        safety: "review".into(),
        state: if users.is_empty() { "open" } else { "in_use" }.into(),
        in_use_by: users,
        why: "A big folder nothing changed in for months, and no recipe knows it. Ask what it is before it goes.".into(),
        regenerate: String::new(),
        how: "trash".into(),
        copies: Vec::new(),
        decision: None,
    }
}

fn duplicate_item(id: String, set: dupes::Set, snapshot: &Snapshot) -> Item {
    let lossless = cfg!(target_os = "macos");
    let users: Vec<String> = set.copies.iter().flat_map(|c| snapshot.users(c, None, None)).collect();
    let mb = set.len / (1024 * 1024);
    Item {
        id,
        path: set.keep.to_string_lossy().into_owned(),
        title: format!("Same {mb} MB file ×{}", set.copies.len() + 1),
        kind: "duplicate".into(),
        recipe: "duplicate".into(),
        bytes: set.reclaim,
        files: set.copies.len() as u64,
        newest_ms: set.newest_ms,
        project: String::new(),
        scope: "copies".into(),
        safety: if lossless { "regenerable" } else { "review" }.into(),
        state: if users.is_empty() { "open" } else { "in_use" }.into(),
        in_use_by: users,
        why: if lossless {
            "The same bytes in several places. The copies become clones of the oldest one: every path keeps its file, the space is shared.".into()
        } else {
            "The same bytes in several places; the copies go to the Trash, the oldest stays.".into()
        },
        regenerate: String::new(),
        how: if lossless { "clone" } else { "trash" }.into(),
        copies: set.copies.into_iter().map(|c| c.to_string_lossy().into_owned()).collect(),
        decision: None,
    }
}

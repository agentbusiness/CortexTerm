//! Cleaning one item, checked again just before: the path is still there, is not a link, belongs
//! to this user, lies on the scanned disk (not one of its top folders) and outside the places
//! that are never touched, git tracks nothing in it, and no program uses it now. Then, by its `how`:
//!
//! - `delete`: removed (regenerable things only);
//! - `trash`: moved to the Trash, so it can be put back;
//! - `command`: the tool's own command (`brew cleanup`, `go clean -modcache`, `git worktree
//!   remove`), which keeps the tool's records right;
//! - `clone`: duplicate copies become APFS clones of the one that stays;
//! - `empty`: the Trash's contents removed.
//!
//! A `stale` item removes only the parts worked out afresh now (stale.rs).

use crate::inuse::Snapshot;
use crate::recipes::{self, Recipe};
use crate::{dupes, git, stale, walk};
use cc_protocol::contracts::cleanup::Item;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Places that are never cleaned, whatever a recipe or the model says.
pub const NEVER: &[&str] = &[
    "~/.ssh", "~/.gnupg", "~/.aws", "~/.kube", "~/.config/gh", "~/.password-store",
    "~/Library/Keychains", "~/Library/Mail", "~/Library/Messages", "~/Library/Mobile Documents",
    "~/Library/CloudStorage", "~/Library/Photos", "~/Pictures/Photos Library.photoslibrary",
    "~/Library/Application Support/MobileSync", "~/.cortexterm", "~/.cortexcode", "~/.cortex-models",
    // Package managers' installs: their own clean commands handle them.
    "/opt/homebrew", "/usr/local/Cellar", "/usr/local/Homebrew", "/usr/local/Caskroom", "/nix",
];

/// Why `path` may not be touched, or Ok.
pub fn guard(path: &Path, home: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|_| "it is no longer there".to_owned())?;
    if meta.file_type().is_symlink() {
        return Err("it is a symbolic link now".into());
    }
    if meta.uid() != walk::uid() {
        return Err("it belongs to another user".into());
    }
    let roots = walk::roots(home);
    if home.starts_with(path) || roots.iter().any(|root| root.starts_with(path)) || !roots.iter().any(|root| path.starts_with(root)) {
        return Err("it is not inside a folder the scan reads".into());
    }
    if NEVER.iter().any(|never| path.starts_with(recipes::expand(never, home)) || recipes::expand(never, home).starts_with(path)) {
        return Err("this place is never cleaned".into());
    }
    Ok(())
}

pub struct Done {
    pub freed: u64,
}

/// Clean `item` now. `snapshot` is taken just before (who uses what).
pub fn clean(item: &Item, home: &Path, snapshot: &Snapshot) -> Result<Done, String> {
    let path = PathBuf::from(&item.path);
    let all = recipes::load().unwrap_or_default();
    let recipe: Option<&Recipe> = all.iter().find(|r| r.id == item.recipe);
    if item.how != "clone" {
        guard(&path, home)?;
    }
    // A repository goes only to the Trash, whole.
    if item.how != "trash" && path.join(".git").is_dir() {
        return Err("it is a git repository".into());
    }
    if item.recipe != "duplicate" && item.recipe != "stale-folder" && item.kind != "trash" && git::tracked(&path) {
        return Err("git tracks files in it".into());
    }
    let project = (!item.project.is_empty()).then(|| PathBuf::from(&item.project));
    let users = match item.how.as_str() {
        "clone" => item.copies.iter().flat_map(|c| snapshot.users(Path::new(c), None, None)).collect(),
        _ if item.scope == "stale" => snapshot.users(&path, None, recipe),
        _ => snapshot.users(&path, project.as_deref(), recipe),
    };
    if !users.is_empty() {
        return Err(format!("in use: {}", users.join(", ")));
    }
    if recipe.is_some_and(|r| r.worktree) {
        let work = git::worktree_work(&path);
        if !work.is_empty() {
            return Err(work.join(", "));
        }
    }
    match item.how.as_str() {
        "clone" => clone_copies(item, home),
        "empty" => empty(&path),
        "command" => command(recipe.ok_or("its recipe is gone")?, &path, project.as_deref()),
        "trash" => {
            let freed = walk::measure(&path).bytes;
            trash(&path, home)?;
            Ok(Done { freed })
        }
        "delete" if item.safety == "regenerable" => {
            let parts = if item.scope == "stale" { stale::cargo(&path) } else { vec![path.clone()] };
            let mut freed = 0;
            for part in parts {
                freed += walk::measure(&part).bytes;
                remove(&part)?;
            }
            Ok(Done { freed })
        }
        _ => Err("this item cannot be deleted outright".into()),
    }
}

fn remove(path: &Path) -> Result<(), String> {
    let meta = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    // remove_dir_all never follows symbolic links inside.
    let result = if meta.is_dir() { std::fs::remove_dir_all(path) } else { std::fs::remove_file(path) };
    result.map_err(|e| format!("{}: {e}", path.display()))
}

/// Into the Trash under a free name (`name 2026-11-01 14.03.22`).
fn trash(path: &Path, home: &Path) -> Result<(), String> {
    let bin = if cfg!(target_os = "macos") { home.join(".Trash") } else { home.join(".local/share/Trash/files") };
    std::fs::create_dir_all(&bin).map_err(|e| e.to_string())?;
    let name = path.file_name().ok_or("no name")?.to_string_lossy().into_owned();
    let mut target = bin.join(&name);
    if target.exists() {
        target = bin.join(format!("{name} {}", cc_protocol::contracts::now_ms()));
    }
    std::fs::rename(path, &target).map_err(|e| format!("moving to the Trash: {e}"))
}

fn empty(trash_dir: &Path) -> Result<Done, String> {
    let mut freed = 0;
    for entry in std::fs::read_dir(trash_dir).map_err(|e| e.to_string())?.flatten() {
        freed += walk::measure(&entry.path()).bytes;
        remove(&entry.path())?;
    }
    Ok(Done { freed })
}

fn clone_copies(item: &Item, home: &Path) -> Result<Done, String> {
    let keep = PathBuf::from(&item.path);
    let mut freed = 0;
    let mut problems = Vec::new();
    for copy in &item.copies {
        let copy = PathBuf::from(copy);
        if let Err(why) = guard(&copy, home) {
            problems.push(format!("{}: {why}", copy.display()));
            continue;
        }
        let before = dupes::private_size(&copy).unwrap_or(0);
        #[cfg(target_os = "macos")]
        let done = dupes::clone_over(&keep, &copy);
        #[cfg(not(target_os = "macos"))]
        let done = if dupes::full(&keep) == dupes::full(&copy) { trash(&copy, home) } else { Err("the files differ now".into()) };
        match done {
            Ok(()) => freed += before,
            Err(why) => problems.push(format!("{}: {why}", copy.display())),
        }
    }
    if freed == 0 && !problems.is_empty() {
        return Err(problems.join("; "));
    }
    Ok(Done { freed })
}

/// The tool's own command, split on spaces after `{path}`, `{name}` (the path's last part) and
/// `{project}` are filled in as whole arguments; no shell. Ten minutes at most.
fn command(recipe: &Recipe, path: &Path, project: Option<&Path>) -> Result<Done, String> {
    let before = walk::measure(path).bytes;
    let mut words = recipe.command.split_whitespace().map(|word| match word {
        "{path}" => path.to_string_lossy().into_owned(),
        "{name}" => path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        "{project}" => project.map(|p| p.to_string_lossy().into_owned()).unwrap_or_default(),
        other => other.to_owned(),
    });
    let program = words.next().ok_or("the recipe has no command")?;
    let mut child = Command::new(&program)
        .args(words)
        .current_dir(project.filter(|p| p.is_dir()).unwrap_or(path.parent().unwrap_or(path)))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|e| e.to_string())? {
            if !status.success() {
                return Err(format!("{} failed ({status})", recipe.command));
            }
            break;
        }
        if started.elapsed() > Duration::from_secs(600) {
            let _ = child.kill();
            return Err(format!("{} took more than ten minutes", recipe.command));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    Ok(Done { freed: before.saturating_sub(walk::measure(path).bytes) })
}

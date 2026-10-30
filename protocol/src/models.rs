//! The models folder every Cortex app shares (`docs/SHARED-MODELS.md`): `~/.cortex-models`, laid
//! out `<org>-<repo>/<revision>/<file>`. Models are read and downloaded only there; a download holds
//! `<org>-<repo>/<revision>/.download.lock`, so two apps that want the same model fetch it once.
//!
//! On every start, before its first model lookup, a plugin moves its own old model folder in
//! ([`move_old`]): a revision missing here is renamed in whole; one already here takes each file not
//! here yet, and the old copy of a file already here at the same size is deleted. Nothing is copied:
//! a rename that fails (another volume, permissions) leaves the old copy where it is.

use std::fs::File;
use std::path::{Path, PathBuf};

/// The lock a download of one revision holds (in `<org>-<repo>/<revision>/`).
pub const DOWNLOAD_LOCK: &str = ".download.lock";

/// `~/.cortex-models`.
pub fn dir() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default().join(".cortex-models")
}

/// `dir` (and the shared folder, 0755) created, and its download lock held until the file is dropped.
/// Blocks while another app downloads into it.
pub fn lock(dir: &Path) -> std::io::Result<File> {
    create(dir)?;
    let file = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(dir.join(DOWNLOAD_LOCK))?;
    file.lock()?;
    Ok(file)
}

fn create(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    std::fs::DirBuilder::new().recursive(true).mode(0o755).create(path)
}

/// Move the model folder `old` (`<old>/<org>-<repo>/<revision>/…`) into the shared folder, then
/// remove the folders that are left empty, `old` included.
pub fn move_old(old: &Path) {
    let shared = dir();
    let same = |a: &Path, b: &Path| std::fs::canonicalize(a).ok().is_some_and(|a| std::fs::canonicalize(b).is_ok_and(|b| a == b));
    if !old.is_dir() || same(old, &shared) {
        return;
    }
    for repo in subdirs(old) {
        let Some(repo_name) = repo.file_name() else { continue };
        for revision in subdirs(&repo) {
            let Some(revision_name) = revision.file_name() else { continue };
            move_revision(&revision, &shared.join(repo_name).join(revision_name));
        }
        let _ = std::fs::remove_dir(&repo);
    }
    let _ = std::fs::remove_dir(old);
}

fn move_revision(from: &Path, to: &Path) {
    let files = files(from);
    // A lock someone holds: still being downloaded (or checked); the next start looks again.
    if files.iter().any(|file| file.extension().is_some_and(|e| e == "lock") && held(&from.join(file))) {
        return;
    }
    for part in files.iter().filter(|file| file.extension().is_some_and(|e| e == "part")) {
        let _ = std::fs::remove_file(from.join(part));
    }
    let files: Vec<&PathBuf> = files.iter().filter(|file| !file.extension().is_some_and(|e| e == "part")).collect();
    let bytes: u64 = files.iter().map(|file| size(&from.join(file)).unwrap_or(0)).sum();
    if !to.exists() {
        let renamed = to.parent().map_or(Ok(()), create).and_then(|()| std::fs::rename(from, to));
        match renamed {
            Ok(()) => tracing::info!(from = %from.display(), to = %to.display(), bytes, "moved a model folder into the shared models folder"),
            Err(error) => tracing::warn!(from = %from.display(), to = %to.display(), %error, "cannot move a model folder into the shared models folder; left where it is"),
        }
        return;
    }
    let Ok(lock) = std::fs::OpenOptions::new().create(true).truncate(false).read(true).write(true).open(to.join(DOWNLOAD_LOCK)) else { return };
    if lock.try_lock().is_err() {
        return;
    }
    let (mut moved, mut deleted, mut kept) = (0u64, 0u64, 0usize);
    for file in files {
        let (source, target) = (from.join(file), to.join(file));
        let bytes = size(&source).unwrap_or(0);
        match size(&target) {
            None => match target.parent().map_or(Ok(()), create).and_then(|()| std::fs::rename(&source, &target)) {
                Ok(()) => moved += bytes,
                Err(error) => {
                    kept += 1;
                    tracing::warn!(from = %source.display(), %error, "cannot move a model file into the shared models folder; left where it is");
                }
            },
            // Same repository, same commit, same size: the same file.
            Some(other) if other == bytes => {
                if std::fs::remove_file(&source).is_ok() {
                    deleted += bytes;
                }
            }
            // The owner's pinned check settles which one is right.
            Some(_) => kept += 1,
        }
    }
    drop(lock);
    remove_empty(from);
    tracing::info!(from = %from.display(), to = %to.display(), moved, deleted, kept, "merged a model folder into the shared models folder");
}

fn subdirs(dir: &Path) -> Vec<PathBuf> {
    let Ok(entries) = std::fs::read_dir(dir) else { return Vec::new() };
    entries.flatten().filter(|entry| entry.file_type().is_ok_and(|t| t.is_dir())).map(|entry| entry.path()).collect()
}

/// Every file below `dir`, relative to it.
fn files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut pending = vec![PathBuf::new()];
    while let Some(relative) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(dir.join(&relative)) else { continue };
        for entry in entries.flatten() {
            let path = relative.join(entry.file_name());
            match entry.file_type() {
                Ok(t) if t.is_dir() => pending.push(path),
                Ok(_) => out.push(path),
                Err(_) => {}
            }
        }
    }
    out
}

fn size(path: &Path) -> Option<u64> {
    std::fs::symlink_metadata(path).ok().filter(|meta| meta.is_file()).map(|meta| meta.len())
}

fn held(path: &Path) -> bool {
    std::fs::OpenOptions::new().read(true).write(true).open(path).is_ok_and(|file| file.try_lock().is_err())
}

/// Remove `dir`'s empty folders, deepest first, `dir` included.
fn remove_empty(dir: &Path) {
    for sub in subdirs(dir) {
        remove_empty(&sub);
    }
    let _ = std::fs::remove_dir(dir);
}

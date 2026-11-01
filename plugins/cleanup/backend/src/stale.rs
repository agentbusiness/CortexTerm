//! A Rust `target` folder of a project in use: what cargo will not use again. Measured at scan
//! time and worked out afresh just before a clean, so a build in between is respected.
//!
//! - A profile (`debug`, `release`, `<triple>/debug`…) not built for 30 days while another one
//!   was goes whole.
//! - In `deps`, `build`, `.fingerprint` and `incremental`, cargo names each unit
//!   `<name>-<16 hex hash>`. When a name has more than one hash, a hash not built within 30 days
//!   of that name's newest one is an older build (other features, another rustc) and goes.
//! - In `incremental/<crate>-<hash>/`, rustc's older `s-…` sessions go; the newest one stays.

use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

const DAY_MS: u64 = 86_400_000;
const OLDER: u64 = 30 * DAY_MS;

fn mtime_ms(path: &Path) -> u64 {
    std::fs::symlink_metadata(path).map(|m| (m.mtime().max(0) as u64) * 1000).unwrap_or(0)
}

fn children(dir: &Path) -> Vec<PathBuf> {
    std::fs::read_dir(dir).map(|e| e.flatten().map(|e| e.path()).collect()).unwrap_or_default()
}

/// The profile folders: those holding a `.fingerprint` folder, one or two levels down.
fn profiles(target: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for child in children(target) {
        if child.join(".fingerprint").is_dir() {
            out.push(child);
        } else if child.is_dir() {
            out.extend(children(&child).into_iter().filter(|p| p.join(".fingerprint").is_dir()));
        }
    }
    out
}

/// When a profile was last built: its newest unit fingerprint.
fn built_ms(profile: &Path) -> u64 {
    children(&profile.join(".fingerprint")).iter().map(|p| mtime_ms(p)).max().unwrap_or(0)
}

/// `libserde-0123456789abcdef.rlib` -> ("libserde", "0123456789abcdef").
fn unit(name: &str) -> Option<(String, String)> {
    let stem = name.split('.').next().unwrap_or(name);
    let (base, hash) = stem.rsplit_once('-')?;
    (hash.len() == 16 && hash.chars().all(|c| c.is_ascii_hexdigit())).then(|| (base.to_owned(), hash.to_owned()))
}

/// Older hashes of the same unit name inside one folder.
fn older_units(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut names: HashMap<String, HashMap<String, (u64, Vec<PathBuf>)>> = HashMap::new();
    for path in children(dir) {
        let Some(file) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else { continue };
        let Some((base, hash)) = unit(&file) else { continue };
        let entry = names.entry(base).or_default().entry(hash).or_default();
        entry.0 = entry.0.max(mtime_ms(&path));
        entry.1.push(path);
    }
    for hashes in names.values() {
        if hashes.len() < 2 {
            continue;
        }
        let newest = hashes.values().map(|(at, _)| *at).max().unwrap_or(0);
        for (at, paths) in hashes.values() {
            if *at + OLDER < newest {
                out.extend(paths.iter().cloned());
            }
        }
    }
}

/// rustc's older incremental sessions (`s-…` folders and their `.lock` files).
fn older_sessions(incremental: &Path, out: &mut Vec<PathBuf>) {
    for crate_dir in children(incremental) {
        let mut sessions: Vec<(u64, PathBuf)> = children(&crate_dir)
            .into_iter()
            .filter(|p| p.is_dir() && p.file_name().is_some_and(|n| n.to_string_lossy().starts_with("s-")))
            .map(|p| (mtime_ms(&p), p))
            .collect();
        sessions.sort();
        let Some((newest, _)) = sessions.last().cloned() else { continue };
        for (at, path) in &sessions[..sessions.len() - 1] {
            if at + DAY_MS < newest {
                out.push(path.clone());
                let lock = path.with_extension("lock");
                if lock.exists() {
                    out.push(lock);
                }
            }
        }
    }
}

/// Everything in `target` cargo will not use again.
pub fn cargo(target: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let profiles: Vec<(u64, PathBuf)> = profiles(target).into_iter().map(|p| (built_ms(&p), p)).collect();
    let newest = profiles.iter().map(|(at, _)| *at).max().unwrap_or(0);
    for (at, profile) in &profiles {
        if *at + OLDER < newest {
            out.push(profile.clone());
            continue;
        }
        for sub in ["deps", "build", ".fingerprint", "incremental"] {
            older_units(&profile.join(sub), &mut out);
        }
        older_sessions(&profile.join("incremental"), &mut out);
    }
    out.sort();
    out.dedup();
    // A path inside another one already listed is gone with it.
    let mut kept: Vec<PathBuf> = Vec::new();
    for path in out {
        if !kept.last().is_some_and(|last| path.starts_with(last)) {
            kept.push(path);
        }
    }
    kept
}

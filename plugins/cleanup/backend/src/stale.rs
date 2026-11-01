//! A Rust `target` folder of a project in use: what its latest builds no longer use. Worked out
//! at scan time and again just before a clean, so a build in between is respected.
//!
//! - A profile (`debug`, `release`, `<triple>/debug`…) not built for 30 days while another one
//!   was goes whole.
//! - Otherwise cargo's own record decides. Each unit has a `.fingerprint/<package>-<hash>/`
//!   folder whose JSON lists the fingerprints of the units it was built from, and whose hash file
//!   holds its own (16 hex digits of the little-endian bytes). The latest build of each of the
//!   project's own packages (per profile, target kind and profile settings, so `cargo check` and
//!   `cargo build` both stay) is followed through those links; a unit none of them reaches is
//!   an earlier build (a version bump, other features, an older rustc, a removed dependency) and
//!   its files in `deps`, `build`, `examples` and `.fingerprint` go. A build script's compiled
//!   program stays with its package's run.
//! - In `incremental/<crate>-<id>/`, rustc's older `s-…` sessions go; the newest one stays.

use std::collections::{HashMap, HashSet};
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

fn name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
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

/// The packages of the project: its own and its workspace members' (`dir` and `dir/*` entries).
fn packages(project: &Path) -> HashSet<String> {
    let read = |dir: &Path| -> Option<toml::Table> { std::fs::read_to_string(dir.join("Cargo.toml")).ok()?.parse().ok() };
    let package = |table: &toml::Table| table.get("package")?.get("name")?.as_str().map(str::to_owned);
    let mut out = HashSet::new();
    let Some(top) = read(project) else { return out };
    out.extend(package(&top));
    let members = top.get("workspace").and_then(|w| w.get("members")).and_then(|m| m.as_array()).cloned().unwrap_or_default();
    for member in members.iter().filter_map(|m| m.as_str()) {
        let dirs = match member.strip_suffix("/*") {
            Some(parent) => children(&project.join(parent)),
            None => vec![project.join(member)],
        };
        out.extend(dirs.iter().filter_map(|dir| read(dir)).filter_map(|t| package(&t)));
    }
    out
}

struct Unit {
    profile: usize,
    package: String,
    hash: String,
    /// The fingerprints it was built from.
    deps: Vec<u64>,
    /// Its target kinds (`bin-cc-system`, `lib-serde`…) with their profile settings' hash.
    kinds: Vec<(String, u64)>,
    built_ms: u64,
}

fn read_unit(dir: &Path, profile: usize, own: &mut Vec<u64>) -> Option<Unit> {
    let (package, hash) = name(dir).rsplit_once('-').map(|(p, h)| (p.to_owned(), h.to_owned()))?;
    if hash.len() != 16 {
        return None;
    }
    let mut unit = Unit { profile, package, hash, deps: Vec::new(), kinds: Vec::new(), built_ms: 0 };
    for file in children(dir) {
        let file_name = name(&file);
        if let Some(kind) = file_name.strip_suffix(".json") {
            let Ok(text) = std::fs::read_to_string(&file) else { continue };
            let Ok(json) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
            for dep in json["deps"].as_array().into_iter().flatten() {
                unit.deps.extend(dep.get(3).and_then(|v| v.as_u64()));
            }
            unit.kinds.push((kind.to_owned(), json["profile"].as_u64().unwrap_or(0)));
            unit.built_ms = unit.built_ms.max(mtime_ms(&file));
        } else if !file_name.starts_with("dep-") && !file_name.starts_with("output-") && file_name != "invoked.timestamp" {
            let text = std::fs::read_to_string(&file).unwrap_or_default();
            let hex = text.trim();
            if let (16, Ok(value)) = (hex.len(), u64::from_str_radix(hex, 16)) {
                // The file holds the bytes little-endian first.
                own.push(value.swap_bytes());
            }
        }
    }
    Some(unit)
}

/// Per profile, the unit hashes the latest builds no longer reach. A profile where none of the
/// project's packages was built is left alone.
fn unused_units(project: &Path, profiles: &[PathBuf]) -> Vec<HashSet<String>> {
    let mut unused = vec![HashSet::new(); profiles.len()];
    let packages = packages(project);
    if packages.is_empty() {
        return unused;
    }
    let mut units: Vec<Unit> = Vec::new();
    let mut by_fingerprint: HashMap<u64, usize> = HashMap::new();
    for (index, profile) in profiles.iter().enumerate() {
        for dir in children(&profile.join(".fingerprint")) {
            let mut own = Vec::new();
            if let Some(unit) = read_unit(&dir, index, &mut own) {
                by_fingerprint.extend(own.into_iter().map(|fp| (fp, units.len())));
                units.push(unit);
            }
        }
    }
    // The latest build of each (profile, package, kind, settings); one not built for 30 days
    // while the same kind was built with other settings is old too.
    let mut latest: HashMap<(usize, &str, &str, u64), (u64, usize)> = HashMap::new();
    let mut newest: HashMap<(usize, &str, &str), u64> = HashMap::new();
    for (i, unit) in units.iter().enumerate().filter(|(_, u)| packages.contains(&u.package)) {
        for (kind, settings) in &unit.kinds {
            let slot = latest.entry((unit.profile, &unit.package, kind, *settings)).or_insert((unit.built_ms, i));
            if unit.built_ms > slot.0 {
                *slot = (unit.built_ms, i);
            }
            let top = newest.entry((unit.profile, &unit.package, kind)).or_default();
            *top = (*top).max(unit.built_ms);
        }
    }
    let mut stack: Vec<usize> = latest
        .iter()
        .filter(|((profile, package, kind, _), (at, _))| at + OLDER >= newest[&(*profile, *package, *kind)])
        .map(|(_, (_, i))| *i)
        .collect();
    let mut live = vec![false; units.len()];
    while let Some(i) = stack.pop() {
        if std::mem::replace(&mut live[i], true) {
            continue;
        }
        stack.extend(units[i].deps.iter().filter_map(|fp| by_fingerprint.get(fp)));
    }
    let live_packages: HashSet<(usize, &str)> = units.iter().zip(&live).filter(|(_, l)| **l).map(|(u, _)| (u.profile, u.package.as_str())).collect();
    let built: HashSet<usize> = units.iter().zip(&live).filter(|(u, l)| **l && packages.contains(&u.package)).map(|(u, _)| u.profile).collect();
    for (unit, live) in units.iter().zip(&live) {
        let script = unit.kinds.iter().any(|(kind, _)| kind.starts_with("build-script-build"));
        if !live && built.contains(&unit.profile) && !(script && live_packages.contains(&(unit.profile, unit.package.as_str()))) {
            unused[unit.profile].insert(unit.hash.clone());
        }
    }
    unused
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

/// Everything in `target` the latest builds no longer use.
pub fn cargo(target: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let all = profiles(target);
    let built: Vec<u64> = all.iter().map(|p| built_ms(p)).collect();
    let newest = built.iter().copied().max().unwrap_or(0);
    let mut current = Vec::new();
    for (profile, at) in all.into_iter().zip(built) {
        if at + OLDER < newest {
            out.push(profile);
        } else {
            current.push(profile);
        }
    }
    let project = target.parent().unwrap_or(target);
    for (profile, unused) in current.iter().zip(unused_units(project, &current)) {
        for sub in ["deps", "build", "examples", ".fingerprint"] {
            for path in children(&profile.join(sub)) {
                if unit(&name(&path)).is_some_and(|(_, hash)| unused.contains(&hash)) {
                    out.push(path);
                }
            }
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

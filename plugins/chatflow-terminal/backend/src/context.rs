//! Small, content-only identities of known project inputs. Never capture environment values,
//! secrets or arbitrary model-supplied paths, and never execute a version/configuration command.
//! The identities describe observations, not compatibility or permission to run a remembered fix.

use cc_protocol::sha256;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::sync::Semaphore;

const PREFIX: &str = "project-context-v1:";
const UNKNOWN: &str = "unknown";
const MAX_FILE: u64 = 1024 * 1024;
const MAX_TOTAL: usize = 2 * 1024 * 1024;
const MAX_FOLDERS: usize = 8;
static CAPTURE: Semaphore = Semaphore::const_new(1);
const INPUTS: &[&str] = &[
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "yarn.lock",
    "bun.lock",
    "pyproject.toml",
    "uv.lock",
    ".python-version",
    ".node-version",
    ".nvmrc",
    "go.mod",
    "go.sum",
];

/// Capture once at the foreground turn, before a later background pass learns from it.
pub async fn capture(cwd: &str) -> Vec<String> {
    let cwd = PathBuf::from(cwd);
    if !cwd.is_absolute() {
        return Vec::new();
    }
    // A timed-out filesystem read cannot be forcibly stopped. Keep its permit inside the job
    // until it really exits, so slow/FUSE storage cannot accumulate background reader threads.
    let Ok(permit) = CAPTURE.try_acquire() else {
        return Vec::new();
    };
    let job = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        observe(&cwd)
    });
    tokio::time::timeout(Duration::from_millis(300), job)
        .await
        .ok()
        .and_then(Result::ok)
        .unwrap_or_default()
}

fn observe(cwd: &Path) -> Vec<String> {
    let mut budget = MAX_TOTAL;
    let mut directories = Vec::new();
    for folder in cwd.ancestors().take(MAX_FOLDERS) {
        // A project or its parents cannot borrow the user's unrelated global configuration.
        // Home/root can be the explicit working folder, but are not traversed from below.
        if folder != cwd
            && (folder.parent().is_none()
                || std::env::var_os("HOME").is_some_and(|home| folder == Path::new(&home)))
        {
            break;
        }
        let mut input = Vec::new();
        let mut complete = true;
        let mut present = false;
        for name in INPUTS {
            input.extend_from_slice(name.as_bytes());
            input.push(0);
            match fingerprint(&folder.join(name), &mut budget) {
                Ok(Some(digest)) => {
                    input.extend_from_slice(digest.as_bytes());
                    present = true;
                }
                Ok(None) => input.extend_from_slice(b"absent"),
                Err(()) => {
                    complete = false;
                    input.extend_from_slice(b"unobserved");
                }
            }
            input.push(0);
        }
        directories.push((
            sha256::hex(folder.as_os_str().as_encoded_bytes()),
            input,
            complete,
            present,
        ));
        if folder.join(".git").exists() {
            break;
        }
    }
    let mut observations = Vec::new();
    // A lesson learned inside src/ also depends on the project inputs above src/. Include the
    // absent-file markers in each directory, so adding a new local manifest is a change too.
    for (index, (scope, _, _, _)) in directories.iter().enumerate() {
        let mut input = Vec::new();
        let mut complete = true;
        let mut present = false;
        for (parent, files, read, exists) in &directories[index..] {
            input.extend_from_slice(parent.as_bytes());
            input.extend_from_slice(files);
            complete &= *read;
            present |= *exists;
        }
        let identity = if complete && present {
            sha256::hex(&input)
        } else {
            UNKNOWN.into()
        };
        observations.push(format!("{PREFIX}{scope}:{identity}"));
    }
    observations
}

fn fingerprint(path: &Path, budget: &mut usize) -> Result<Option<String>, ()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(()),
    };
    if !metadata.is_file() || metadata.len() > MAX_FILE || metadata.len() as usize > *budget {
        return Err(());
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| ())?;
    let before = file.metadata().map_err(|_| ())?;
    if !before.is_file() || before.len() > MAX_FILE || before.len() as usize > *budget {
        return Err(());
    }
    // Charge attempted reads too; an I/O error must not reset the allowance for later files.
    *budget = budget.saturating_sub(before.len() as usize);
    let mut bytes = Vec::with_capacity(before.len() as usize);
    (&file)
        .take(before.len().saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    let after = file.metadata().map_err(|_| ())?;
    if bytes.len() as u64 != before.len()
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.len() != after.len()
    {
        return Err(());
    }
    Ok(Some(sha256::hex(&bytes)))
}

/// Explain validity next to the lesson, without erasing useful historical knowledge. An equal
/// fingerprint only establishes that these observed project files match, never tool/runtime state.
pub fn notice(aliases: &[String], current: &[String]) -> &'static str {
    let expected: Vec<&str> = aliases
        .iter()
        .filter_map(|alias| alias.strip_prefix(PREFIX))
        .collect();
    if expected.is_empty() {
        return "Historical lesson: its project inputs were not recorded. Check current conditions before using it.";
    }
    // Current bindings are nearest folder first. Never let a matching parent hide a changed
    // child; multiple saved observations of this same scope may legitimately match either.
    for now in current
        .iter()
        .filter_map(|alias| alias.strip_prefix(PREFIX))
    {
        let Some((current_scope, observed)) = now.split_once(':') else {
            continue;
        };
        let same_scope: Vec<&str> = expected
            .iter()
            .filter_map(|old| {
                let (scope, prior) = old.split_once(':')?;
                (scope == current_scope).then_some(prior)
            })
            .collect();
        if same_scope.is_empty() {
            continue;
        }
        if observed != UNKNOWN {
            if same_scope.contains(&observed) {
                return "Historical lesson: observed project files match a saved example. Actual tool versions and whether the fix still works remain unverified.";
            }
            if same_scope.iter().any(|prior| *prior != UNKNOWN) {
                return "Historical example only: observed project inputs have changed. Recheck this workaround against current evidence; do not present it as a current fix.";
            }
        }
        break;
    }
    "Historical lesson: project compatibility is unknown (different scope, missing, large or unreadable inputs). Check current conditions before using it."
}

pub fn is_binding(alias: &str) -> bool {
    alias.starts_with(PREFIX)
}

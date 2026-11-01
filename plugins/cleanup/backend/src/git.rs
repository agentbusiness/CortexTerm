//! What git says about a folder: tracked files are never cleaned, ambiguous build folders must be
//! ignored, and an agent's worktree with uncommitted work stays.

use std::path::Path;
use std::process::{Command, Stdio};

fn git(dir: &Path, args: &[&str]) -> Option<(i32, String)> {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    Some((output.status.code().unwrap_or(-1), String::from_utf8_lossy(&output.stdout).into_owned()))
}

fn split(path: &Path) -> Option<(&Path, &std::ffi::OsStr)> {
    Some((path.parent()?, path.file_name()?))
}

/// Git tracks a file inside `path` (outside a repository: false).
pub fn tracked(path: &Path) -> bool {
    let Some((dir, name)) = split(path) else { return false };
    let name = name.to_string_lossy();
    git(dir, &["ls-files", "-z", "--", &name]).is_some_and(|(code, out)| code == 0 && !out.is_empty())
}

/// Git ignores `path`: Some(true|false) inside a repository, None outside one.
pub fn ignored(path: &Path) -> Option<bool> {
    let (dir, name) = split(path)?;
    let name = name.to_string_lossy();
    match git(dir, &["check-ignore", "-q", "--", &name])?.0 {
        0 => Some(true),
        1 => Some(false),
        _ => None,
    }
}

/// Why a worktree must stay: uncommitted changes, or commits no branch holds.
pub fn worktree_work(path: &Path) -> Vec<String> {
    let mut why = Vec::new();
    match git(path, &["status", "--porcelain", "--untracked-files=normal"]) {
        Some((0, out)) if !out.trim().is_empty() => why.push(format!("{} uncommitted change(s)", out.lines().count())),
        Some((0, _)) => {}
        _ => why.push("git cannot read this worktree".into()),
    }
    let detached = git(path, &["symbolic-ref", "-q", "HEAD"]).is_none_or(|(code, _)| code != 0);
    if detached && git(path, &["branch", "-a", "--contains", "HEAD"]).is_some_and(|(code, out)| code == 0 && out.trim().is_empty()) {
        why.push("commits on no branch".into());
    }
    why
}

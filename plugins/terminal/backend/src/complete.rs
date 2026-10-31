//! `terminal.complete`: candidates for the word at the cursor, from the terminal's shell (PATH,
//! aliases, functions, builtins), the file system, git branches, ssh hosts and processes, plus a
//! whole-line suggestion from the Run history.

use crate::assess::{BUILTINS, Shell, expand};
use cc_protocol::contracts::terminal::{Completion, Completions};
use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const LIMIT: usize = 200;
/// How long a PATH listing is reused.
const PATH_TTL: Duration = Duration::from_secs(30);

/// Words that run the word after them as a command.
const PREFIXES: &[&str] = &["sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice", "xargs", "watch", "caffeinate"];

const GIT_SUBCOMMANDS: &[&str] = &[
    "add", "bisect", "blame", "branch", "checkout", "cherry-pick", "clean", "clone", "commit", "config", "diff", "fetch",
    "grep", "init", "log", "merge", "mv", "pull", "push", "rebase", "reflog", "remote", "reset", "restore", "revert", "rm",
    "show", "stash", "status", "switch", "tag", "worktree",
];

/// Executables on a PATH, cached for [`PATH_TTL`].
fn path_commands(dirs: &[PathBuf]) -> Arc<Vec<String>> {
    type Cache = Mutex<HashMap<Vec<PathBuf>, (Instant, Arc<Vec<String>>)>>;
    static CACHE: OnceLock<Cache> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Some((at, list)) = crate::lock(cache).get(dirs)
        && at.elapsed() < PATH_TTL
    {
        return list.clone();
    }
    use std::os::unix::fs::PermissionsExt;
    let mut names = std::collections::BTreeSet::new();
    for dir in dirs {
        for entry in std::fs::read_dir(dir).into_iter().flatten().flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_file() && meta.permissions().mode() & 0o111 != 0 {
                names.insert(entry.file_name().to_string_lossy().into_owned());
            }
        }
    }
    let list = Arc::new(names.into_iter().collect::<Vec<_>>());
    crate::lock(cache).insert(dirs.to_vec(), (Instant::now(), list.clone()));
    list
}

fn item(value: String, kind: &str, description: impl Into<String>) -> Completion {
    Completion { value, kind: kind.into(), description: description.into() }
}

/// Backslash-escape what the shell would split or expand.
pub(crate) fn escape(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if " \t'\"\\$`&|;<>()[]*?!#{}~".contains(c) {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

fn unescape(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    let mut chars = word.chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' => out.extend(chars.next()),
            '\'' | '"' => {}
            other => out.push(other),
        }
    }
    out
}

/// Start of the word that ends at `cursor` (a backslash-escaped space stays in the word).
fn word_start(line: &str, cursor: usize) -> usize {
    let bytes = line.as_bytes();
    let mut start = cursor;
    while start > 0 {
        let c = bytes[start - 1];
        let escaped = start >= 2 && bytes[start - 2] == b'\\';
        if (c.is_ascii_whitespace() || b"|;&<>()`".contains(&c)) && !escaped {
            break;
        }
        start -= 1;
    }
    start
}

pub fn complete(line: &str, cursor: usize, shell: &Shell, suggestion: Option<String>) -> Completions {
    let mut cursor = cursor.min(line.len());
    while !line.is_char_boundary(cursor) {
        cursor -= 1;
    }
    let from = word_start(line, cursor);
    let word = &line[from..cursor];
    // The words of this command before the one being completed.
    let before = &line[..from];
    let segment = before.rsplit(['|', ';', '&', '(', '\n', '`']).next().unwrap_or("");
    let mut words: Vec<&str> = segment.split_whitespace().collect();
    while let Some(first) = words.first()
        && (PREFIXES.contains(first) || first.contains('='))
    {
        words.remove(0);
    }
    let (items, start) = if words.is_empty() {
        (commands(word, shell), from)
    } else {
        context(&words, word, from, shell)
    };
    Completions { from: start as u32, items, suggestion }
}

fn context(words: &[&str], word: &str, from: usize, shell: &Shell) -> (Vec<Completion>, usize) {
    let command = words[0].rsplit('/').next().unwrap_or(words[0]);
    if word.starts_with('-') || word.contains('$') {
        return (Vec::new(), from);
    }
    match command {
        "cd" | "pushd" | "rmdir" | "z" => (files(word, shell.cwd, true), from),
        "git" if words.len() == 1 => {
            let items = GIT_SUBCOMMANDS.iter().filter(|s| s.starts_with(word)).map(|s| item((*s).to_owned(), "command", "git")).collect();
            (items, from)
        }
        "git" if matches!(words.get(1).copied(), Some("checkout" | "switch" | "branch" | "merge" | "rebase")) => {
            (branches(word, shell.cwd), from)
        }
        "ssh" | "mosh" | "sftp" | "scp" if !word.contains('/') && !word.starts_with('.') && !word.contains(':') => {
            let (user, host) = match word.rfind('@') {
                Some(at) => (at + 1, &word[at + 1..]),
                None => (0, word),
            };
            let mut items = hosts(host);
            if command == "scp" {
                items.extend(files(word, shell.cwd, false));
            }
            (items, from + user)
        }
        "kill" => (processes(word), from),
        _ => (files(word, shell.cwd, false), from),
    }
}

fn commands(prefix: &str, shell: &Shell) -> Vec<Completion> {
    if prefix.contains('/') {
        return files(prefix, shell.cwd, false);
    }
    let mut found: BTreeMap<String, Completion> = BTreeMap::new();
    if "edit".starts_with(prefix) {
        found.insert("edit".into(), item("edit".into(), "command", "CortexTerm file editor"));
    }
    for (name, value) in &shell.env.aliases {
        if name.starts_with(prefix) {
            found.insert(name.clone(), item(name.clone(), "command", format!("alias: {value}")));
        }
    }
    for name in &shell.env.functions {
        if name.starts_with(prefix) && !found.contains_key(name) {
            found.insert(name.clone(), item(name.clone(), "command", "function"));
        }
    }
    for name in BUILTINS {
        if name.starts_with(prefix) && !found.contains_key(*name) {
            found.insert((*name).to_owned(), item((*name).to_owned(), "command", "builtin"));
        }
    }
    for name in path_commands(&shell.path_dirs()).iter() {
        if name.starts_with(prefix) && !found.contains_key(name) {
            found.insert(name.clone(), item(name.clone(), "command", ""));
        }
    }
    let mut items: Vec<Completion> = found.into_values().collect();
    items.sort_by(|a, b| a.value.len().cmp(&b.value.len()).then_with(|| a.value.cmp(&b.value)));
    items.truncate(LIMIT);
    items
}

fn files(word: &str, cwd: &Path, dirs_only: bool) -> Vec<Completion> {
    let typed = unescape(word);
    let (dir_part, prefix) = match typed.rfind('/') {
        Some(i) => (&typed[..=i], &typed[i + 1..]),
        None => ("", typed.as_str()),
    };
    let dir = if dir_part.is_empty() { cwd.to_path_buf() } else { expand(dir_part, cwd) };
    let mut exact = Vec::new();
    let mut loose = Vec::new();
    let lower = prefix.to_lowercase();
    for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && !prefix.starts_with('.') {
            continue;
        }
        let is_dir = std::fs::metadata(entry.path()).is_ok_and(|m| m.is_dir());
        if dirs_only && !is_dir {
            continue;
        }
        let value = format!("{}{}{}", escape_dir(dir_part), escape(&name), if is_dir { "/" } else { "" });
        let completion = item(value, if is_dir { "dir" } else { "file" }, "");
        if name.starts_with(prefix) {
            exact.push(completion);
        } else if name.to_lowercase().starts_with(&lower) {
            loose.push(completion);
        }
    }
    let mut items = if exact.is_empty() { loose } else { exact };
    items.sort_by(|a, b| a.value.cmp(&b.value));
    items.truncate(LIMIT);
    items
}

/// The folder part as typed (`~/` stays), escaped again.
fn escape_dir(dir: &str) -> String {
    match dir.strip_prefix('~') {
        Some(rest) => format!("~{}", escape(rest)),
        None => escape(dir),
    }
}

fn branches(prefix: &str, cwd: &Path) -> Vec<Completion> {
    let Ok(output) = std::process::Command::new("git")
        .args(["for-each-ref", "--format=%(refname:short)", "refs/heads"])
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|b| b.starts_with(prefix))
        .take(LIMIT)
        .map(|b| item(b.to_owned(), "branch", ""))
        .collect()
}

fn hosts(prefix: &str) -> Vec<Completion> {
    let home = std::env::var("HOME").unwrap_or_default();
    let text = std::fs::read_to_string(Path::new(&home).join(".ssh").join("config")).unwrap_or_default();
    let mut found = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some((key, rest)) = line.split_once(char::is_whitespace) else { continue };
        if !key.eq_ignore_ascii_case("host") {
            continue;
        }
        for host in rest.split_whitespace() {
            if !host.contains(['*', '?', '!']) && host.starts_with(prefix) && !found.iter().any(|c: &Completion| c.value == host) {
                found.push(item(host.to_owned(), "host", "ssh config"));
            }
        }
    }
    found.truncate(LIMIT);
    found
}

fn processes(prefix: &str) -> Vec<Completion> {
    // SAFETY: getuid has no failure modes.
    let uid = unsafe { libc::getuid() };
    let Ok(output) = std::process::Command::new("ps")
        .args(["-U", &uid.to_string(), "-o", "pid=,comm="])
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .output()
    else {
        return Vec::new();
    };
    let digits = !prefix.is_empty() && prefix.chars().all(|c| c.is_ascii_digit());
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            let (pid, command) = line.split_once(char::is_whitespace)?;
            let name = command.trim().rsplit('/').next().unwrap_or(command).to_owned();
            let keep = prefix.is_empty() || if digits { pid.starts_with(prefix) } else { name.starts_with(prefix) };
            keep.then(|| item(pid.to_owned(), "process", name))
        })
        .take(LIMIT)
        .collect()
}

//! Places and habits: what the Runs say about a folder (`terminal.habits`), and what CortexTerm
//! learns from them into its memory (the memory plugin's global IronGraph, through the frame).
//!
//! Habits are computed from the Run store for the folder and the folders above it (up to, not
//! including, the home folder): the commands used most, the share that ended with exit 0, the
//! usual (median) duration and the last time.
//!
//! Learning: after Runs finish, the [`Learner`] waits until the terminal has been quiet for a
//! while (and at least a few minutes since it last learned), then writes per-folder facts as
//! global `memory.knowledge.upsert` items of kind `fact` (source `inferred`, by `terminal`). Their
//! names start with `place <path>: `, so upserting the same name again updates the fact instead
//! of adding a twin, and `memory.knowledge.list` finds them again:
//! - `place <path>: habits`: "In ~/dev/web-api you usually run `make dev` (12 runs, ok 92%)";
//! - `place <path>: fix for <command>`: a command that failed, then passed within ten minutes
//!   with another command run (successfully) in between: "In ~/dev/web-api, `cargo test` failed
//!   3 times and then passed after `docker compose up -d db`".
//!
//! `terminal.habits` returns the habits with those facts as `notes`; `terminal.places` adds the
//! folders known from memory to those of the Run store.

use crate::lock;
use crate::store::Store;
pub use crate::store::Memory;
use cc_protocol::contracts::memory::{KnowledgeItem, KnowledgeListResult, KnowledgeUpsertParams, methods as memory};
use cc_protocol::contracts::terminal::{Habit, Run};
use cc_protocol::{RpcError, to_value};
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::Notify;

const PREFIX: &str = "place ";
/// Learn once no Run has finished for this long...
const QUIET: Duration = Duration::from_secs(20);
/// ...and at most this often.
const EVERY: Duration = Duration::from_secs(180);
/// A failure counts as fixed when the same command passes within this time.
const FIX_WINDOW_MS: u64 = 10 * 60 * 1000;
/// A habit needs this many Runs.
const MIN_RUNS: u64 = 3;
/// Commands that look around rather than change anything: never the fix.
const TRIVIAL: &[&str] = &["cd", "ls", "ll", "la", "l", "pwd", "clear", "echo", "cat", "less", "more", "history", "exit", "z", "tree", "which", "type"];

/// The folder and the folders above it, nearest first: for a folder below the home folder up to
/// (not including) the home folder, else up to (not including) `/`.
pub fn scope(cwd: &str) -> Vec<String> {
    let home = std::env::var("HOME").unwrap_or_default();
    let below_home = !home.is_empty() && cwd.starts_with(&format!("{home}/"));
    let mut folders = vec![cwd.to_owned()];
    for dir in Path::new(cwd).ancestors().skip(1) {
        let dir = dir.to_string_lossy();
        if dir == "/" || dir.is_empty() || (below_home && (dir == home || !dir.starts_with(&home))) {
            break;
        }
        folders.push(dir.into_owned());
    }
    folders
}

/// `~/x` for a folder below the home folder.
fn tilde(path: &str) -> String {
    let home = std::env::var("HOME").unwrap_or_default();
    match path.strip_prefix(&home) {
        Some(rest) if !home.is_empty() && (rest.is_empty() || rest.starts_with('/')) => format!("~{rest}"),
        _ => path.to_owned(),
    }
}

fn percent(share: f32) -> u32 {
    (share * 100.0).round() as u32
}

fn trivial(command: &str) -> bool {
    command.split_whitespace().next().is_none_or(|word| TRIVIAL.contains(&word))
}

/// Programs whose first word is a subcommand (`git push`, `npm install`).
const SUBCOMMANDS: &[&str] = &[
    "git", "npm", "pnpm", "yarn", "bun", "cargo", "go", "docker", "podman", "kubectl", "brew", "pip", "pip3", "uv", "pipx", "gh",
    "launchctl", "defaults", "security", "systemctl", "diskutil", "tmutil", "hdiutil", "gem", "poetry", "conda", "helm", "terraform",
    "aws", "gcloud", "az", "xcrun", "swift", "rustup", "nvm", "make", "just", "spctl", "csrutil", "networksetup", "dscl", "log",
];

/// The shape of each command in a line, for "first time anything like this ran here": the
/// program, its subcommand and its flags (sorted, without their values), so `git push -f origin
/// main` is `git push -f`. Paths, names and values do not count.
pub fn shapes(line: &str) -> Vec<String> {
    let Ok(cmds) = crate::assess::parse(line) else { return Vec::new() };
    cmds.iter()
        .filter_map(|cmd| {
            let words: Vec<&str> = cmd.words.iter().map(|w| w.text.as_str()).skip_while(|w| w.contains('=') && !w.starts_with('-')).collect();
            let program = words.first()?.rsplit('/').next()?;
            let mut shape = vec![program.to_owned()];
            if SUBCOMMANDS.contains(&program)
                && let Some(sub) = words[1..].iter().find(|w| !w.starts_with('-'))
                && sub.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == ':')
            {
                shape.push((*sub).to_owned());
            }
            let mut flags: Vec<String> = words[1..]
                .iter()
                .filter(|w| w.starts_with('-') && w.len() > 1)
                .map(|w| {
                    let flag = w.split('=').next().unwrap_or(w);
                    if flag.starts_with("--") {
                        flag.to_owned()
                    } else {
                        // `-rf` and `-fr` are the same flags.
                        let mut letters: Vec<char> = flag[1..].chars().collect();
                        letters.sort_unstable();
                        letters.dedup();
                        format!("-{}", letters.into_iter().collect::<String>())
                    }
                })
                .collect();
            flags.sort();
            flags.dedup();
            shape.extend(flags);
            Some(shape.join(" "))
        })
        .collect()
}

/// The latest learned fix per failing command: (command, failures, fix).
fn fixes(runs: &[Run]) -> Vec<(String, u32, String)> {
    let mut found: HashMap<String, (u32, String)> = HashMap::new();
    for (i, run) in runs.iter().enumerate() {
        if run.exit_code != Some(0) {
            continue;
        }
        let mut failures = 0u32;
        let mut fix: Option<&str> = None;
        let mut next_start = run.started;
        for earlier in runs[..i].iter().rev() {
            if earlier.command == run.command {
                let failed = earlier.exit_code.is_some_and(|code| code != 0);
                let end = earlier.ended.unwrap_or(earlier.started);
                if !failed || next_start.saturating_sub(end) > FIX_WINDOW_MS {
                    break;
                }
                failures += 1;
                next_start = earlier.started;
            } else if failures == 0 {
                if run.started.saturating_sub(earlier.ended.unwrap_or(earlier.started)) > FIX_WINDOW_MS {
                    break;
                }
                if fix.is_none() && earlier.exit_code == Some(0) && !trivial(&earlier.command) {
                    fix = Some(&earlier.command);
                }
            } else {
                // Another command before the failures: the streak is over.
                break;
            }
        }
        if failures > 0
            && let Some(fix) = fix
        {
            found.insert(run.command.clone(), (failures, fix.to_owned()));
        }
    }
    let mut fixes: Vec<(String, u32, String)> = found.into_iter().map(|(command, (n, fix))| (command, n, fix)).collect();
    fixes.sort();
    fixes
}

/// What to remember about `cwd`: (name, text) facts.
pub async fn facts(store: &Store, cwd: &str) -> Result<Vec<(String, String)>, RpcError> {
    let place = tilde(cwd);
    let mut facts = Vec::new();
    let habits: Vec<Habit> = store.habits(&[cwd.to_owned()], 3).await?.into_iter().filter(|h| h.runs >= MIN_RUNS).collect();
    if !habits.is_empty() {
        let list = habits
            .iter()
            .map(|h| format!("`{}` ({} runs, ok {}%)", h.command, h.runs, percent(h.success)))
            .collect::<Vec<_>>()
            .join(", ");
        facts.push((format!("{PREFIX}{cwd}: habits"), format!("In {place} you usually run {list}")));
    }
    for (command, failures, fix) in fixes(&store.folder_runs(cwd, 500).await?) {
        let times = if failures == 1 { "once".to_owned() } else { format!("{failures} times") };
        facts.push((
            format!("{PREFIX}{cwd}: fix for {command}"),
            format!("In {place}, `{command}` failed {times} and then passed after `{fix}`"),
        ));
    }
    Ok(facts)
}

/// The folder a learned fact is about.
fn fact_place(item: &KnowledgeItem) -> Option<&str> {
    let rest = item.name.strip_prefix(PREFIX)?;
    let (path, _) = rest.split_once(": ")?;
    path.starts_with('/').then_some(path)
}

pub struct Learner {
    store: Arc<Store>,
    memory: Memory,
    dirty: Mutex<HashSet<String>>,
    /// What was last written per fact name (nothing is written again unchanged).
    written: Mutex<HashMap<String, String>>,
    wake: Notify,
}

impl Learner {
    pub fn new(store: Arc<Store>, memory: Memory) -> Arc<Self> {
        let learner = Arc::new(Self {
            store,
            memory,
            dirty: Mutex::new(HashSet::new()),
            written: Mutex::new(HashMap::new()),
            wake: Notify::new(),
        });
        tokio::spawn(learner.clone().run());
        learner
    }

    /// A Run finished in `cwd`.
    pub fn touch(&self, cwd: &str) {
        if cwd.starts_with('/') {
            lock(&self.dirty).insert(cwd.to_owned());
            self.wake.notify_one();
        }
    }

    async fn run(self: Arc<Self>) {
        let mut last: Option<Instant> = None;
        loop {
            self.wake.notified().await;
            while tokio::time::timeout(QUIET, self.wake.notified()).await.is_ok() {}
            if let Some(at) = last {
                tokio::time::sleep(EVERY.saturating_sub(at.elapsed())).await;
            }
            let folders: Vec<String> = lock(&self.dirty).drain().collect();
            for folder in folders {
                if let Err(error) = self.learn(&folder).await {
                    tracing::debug!("habits: cannot learn about {folder}: {error}");
                }
            }
            last = Some(Instant::now());
        }
    }

    /// Write what the Runs say about `cwd` into memory now.
    pub async fn learn(&self, cwd: &str) -> Result<usize, RpcError> {
        let facts = facts(&self.store, cwd).await?;
        let mut written = 0;
        for (name, text) in facts {
            if lock(&self.written).get(&name) == Some(&text) {
                continue;
            }
            let params = KnowledgeUpsertParams {
                kind: "fact".into(),
                name: name.clone(),
                text: text.clone(),
                source: Some("inferred".into()),
                by: "terminal".into(),
                aliases: vec![cwd.to_owned()],
                ..KnowledgeUpsertParams::default()
            };
            let item = (self.memory)(memory::KNOWLEDGE_UPSERT, to_value(&params)?).await?;
            // The habit is about its folder: the edge the model follows from a place to what was learned there.
            if let Some(id) = item.get("id").and_then(|v| v.as_str()) {
                let edge = json!({
                    "nodes": [{"label": "Folder", "key": cwd}],
                    "edges": [{"from": {"label": "Knowledge", "key": id}, "rel": "ABOUT", "to": {"label": "Folder", "key": cwd}}],
                });
                if let Err(error) = (self.memory)(memory::GRAPH_PUT, edge).await {
                    tracing::info!("habit {name}: cannot link it to {cwd}: {}", error.message);
                }
            }
            lock(&self.written).insert(name, text);
            written += 1;
        }
        Ok(written)
    }

    async fn learned(&self) -> Result<Vec<KnowledgeItem>, RpcError> {
        let value = (self.memory)(memory::KNOWLEDGE_LIST, json!({ "kind": "fact" })).await?;
        let list: KnowledgeListResult = serde_json::from_value(value).map_err(|e| RpcError::internal(format!("memory.knowledge.list: {e}")))?;
        Ok(list.items.into_iter().filter(|item| fact_place(item).is_some()).collect())
    }

    /// The facts learned about `cwd` and the folders above it, nearest folder first.
    pub async fn notes(&self, cwd: &str) -> Result<Vec<String>, RpcError> {
        let folders = scope(cwd);
        let mut notes: Vec<(usize, String, String)> = self
            .learned()
            .await?
            .into_iter()
            .filter_map(|item| {
                let at = folders.iter().position(|f| Some(f.as_str()) == fact_place(&item))?;
                Some((at, item.name, item.text))
            })
            .collect();
        notes.sort();
        Ok(notes.into_iter().map(|(_, _, text)| text).collect())
    }

    /// Folders memory knows, with the last time a fact about them changed.
    pub async fn places(&self) -> Result<Vec<(String, u64)>, RpcError> {
        let mut places: HashMap<String, u64> = HashMap::new();
        for item in self.learned().await? {
            if let Some(path) = fact_place(&item) {
                let last = places.entry(path.to_owned()).or_default();
                *last = (*last).max(item.updated_ms);
            }
        }
        Ok(places.into_iter().collect())
    }
}

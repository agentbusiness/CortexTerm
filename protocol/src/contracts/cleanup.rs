//! `cleanup@1`: disk space this computer can get back. A scan walks the whole disk (every folder
//! of the data volume this user can read) for what the cleanup recipes know: build output,
//! package, app and tool caches, AI agents' leftovers, temporary files, big folders untouched for
//! months and large files kept twice. Only this user's files are offered. Each find is a [`Item`] with what it is, how it comes back, and whether a
//! program is using it right now.
//!
//! The person decides per item: clean it, keep it (intended: never scanned again), or not now
//! (skipped for 30 days). "Clean up with AI" asks the local model for a plan over the items;
//! the plugin's code still decides what may run: the model can clean only what is regenerable,
//! idle and not kept, and its other choices stay suggestions. Every find, decision and clean is
//! recorded in the terminal's graph (docs/GRAPH-MODEL.md, "Disk cleanup").

use serde::{Deserialize, Serialize};

pub mod methods {
    /// [`super::ScanParams`] -> [`super::Report`]: start a scan (a running one is left to finish).
    /// Progress arrives as [`events::PROGRESS`]; [`events::CHANGED`] when it is done.
    pub const SCAN: &str = "cleanup.scan";
    /// `{}` -> [`super::Report`]: stop a running scan; what it found so far is kept.
    pub const STOP: &str = "cleanup.stop";
    /// `{}` -> [`super::Report`]: the disk, the last scan and its items.
    pub const STATUS: &str = "cleanup.status";
    /// [`super::ApplyParams`] -> [`super::Applied`]: clean, keep, postpone or reconsider items.
    pub const APPLY: &str = "cleanup.apply";
    /// [`super::ExplainParams`] -> [`super::Explained`]: what an item is, in a few sentences, from
    /// the local model.
    pub const EXPLAIN: &str = "cleanup.explain";
    /// [`super::PlanParams`] -> [`super::Plan`]: the local model's plan over the open items, checked
    /// by the plugin's rules. Applying it is a separate [`APPLY`] with `by: "ai"`.
    pub const PLAN: &str = "cleanup.plan";
    pub const ALL: &[&str] = &[SCAN, STOP, STATUS, APPLY, EXPLAIN, PLAN];
}

pub mod events {
    /// [`super::Progress`], about twice a second while a scan runs.
    pub const PROGRESS: &str = "cleanup.progress";
    /// `{}`: the items changed (a scan finished, an item was cleaned or decided).
    pub const CHANGED: &str = "cleanup.changed";
}

/// What an item is. `build`: a project's build output; `cache`: a tool's or package manager's
/// cache; `agent`: what AI coding agents leave (worktrees, scratch folders, old transcripts);
/// `temp`: temporary files; `model`: downloaded model weights; `stale`: a big folder nobody
/// touched for months; `duplicate`: a large file kept more than once; `trash`: the Trash.
pub const KINDS: &[&str] = &["build", "cache", "agent", "temp", "model", "stale", "duplicate", "trash"];

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScanParams {
    /// Scan again even what a recent scan measured.
    #[serde(default)]
    pub full: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Progress {
    pub scan: String,
    /// `places` (known locations), `walk` (the disk), `duplicates`, `checks` (who uses what).
    pub phase: String,
    pub files: u64,
    pub bytes: u64,
    /// The folder being read, `~`-relative.
    pub folder: String,
    pub found: u32,
    pub found_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Disk {
    pub total: u64,
    pub free: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScanInfo {
    pub id: String,
    pub started_ms: u64,
    /// 0 while it runs.
    pub finished_ms: u64,
    pub files: u64,
    pub bytes: u64,
    /// Stopped before the end.
    #[serde(default)]
    pub stopped: bool,
    /// Folders skipped because the person keeps them.
    #[serde(default)]
    pub skipped_kept: u32,
}

/// One thing that can be cleaned.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Item {
    /// Stable across scans: the path, or `dupe:<hash>` for a set of duplicates.
    pub id: String,
    /// The folder or file (for a duplicate set, the copy that stays).
    pub path: String,
    /// What it is, in a few words ("Rust build output", "Xcode DerivedData").
    pub title: String,
    /// One of [`KINDS`].
    pub kind: String,
    /// The recipe that found it (`cargo-target`, `cachedir-tag`, `stale-folder`…).
    pub recipe: String,
    /// Bytes on disk that cleaning gives back (allocated, hard links counted once).
    pub bytes: u64,
    pub files: u64,
    /// The newest change inside (epoch ms).
    pub newest_ms: u64,
    /// The project it belongs to (the folder with Cargo.toml, package.json…), when there is one.
    #[serde(default)]
    pub project: String,
    /// `whole`: the item goes; `stale`: only its old parts go (older builds), the current ones
    /// stay; `copies`: the other copies of a duplicate become clones of this one (macOS) or go to
    /// the Trash.
    pub scope: String,
    /// `regenerable` (comes back by itself or with `regenerate`), `review` (the person's files,
    /// or not known: only moved to the Trash, and never by the AI alone).
    pub safety: String,
    /// `open`, `in_use` (a program uses it now), `warm` (changed in the last two days, or the
    /// current build of a project being worked on: only the person cleans it), `kept`, `later`,
    /// `cleaned`.
    pub state: String,
    /// Who uses it: `cargo (pid 4182)`, `a build lock is held`.
    #[serde(default)]
    pub in_use_by: Vec<String>,
    /// Why it is here, one line.
    pub why: String,
    /// What brings it back (`cargo build`), when it comes back.
    #[serde(default)]
    pub regenerate: String,
    /// `delete` (regenerable), `trash` (review), `command` (the tool's own clean), `clone` (the
    /// copies become clones of `path`) or `empty` (the Trash's contents removed for good).
    pub how: String,
    /// The other copies (`copies` scope).
    #[serde(default)]
    pub copies: Vec<String>,
    /// The person's or the AI's last word on it.
    #[serde(default)]
    pub decision: Option<Decision>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Decision {
    /// `clean`, `keep`, `later`.
    pub verdict: String,
    /// `user` or `ai`.
    pub by: String,
    #[serde(default)]
    pub reason: String,
    pub at_ms: u64,
    /// `later`: when it comes back (epoch ms).
    #[serde(default)]
    pub until_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Report {
    pub disk: Disk,
    /// The running scan, or the last one.
    pub scan: Option<ScanInfo>,
    pub running: bool,
    pub items: Vec<Item>,
    /// Freed by this plugin, all time.
    pub freed_bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Step {
    pub id: String,
    /// `clean`, `keep` (intended: never scanned again), `later` (30 days), `reset` (forget the
    /// decision; the next scan looks again).
    pub action: String,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ApplyParams {
    pub steps: Vec<Step>,
    /// `user` (default) or `ai`: the AI may only clean regenerable, idle items.
    #[serde(default)]
    pub by: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Outcome {
    pub id: String,
    pub ok: bool,
    #[serde(default)]
    pub freed: u64,
    /// Why it was not done.
    #[serde(default)]
    pub detail: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Applied {
    pub outcomes: Vec<Outcome>,
    pub freed: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ExplainParams {
    pub id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Explained {
    pub text: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PlanParams {
    /// The items to plan for; every open item when empty.
    #[serde(default)]
    pub ids: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PlannedStep {
    pub id: String,
    /// What the model chose: `clean`, `keep`, `later`.
    pub action: String,
    pub reason: String,
    /// The plugin's rules allow the AI to do it; otherwise it is a suggestion for the person.
    pub allowed: bool,
    #[serde(default)]
    pub bytes: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Plan {
    pub steps: Vec<PlannedStep>,
    /// Bytes the allowed `clean` steps give back.
    pub freed: u64,
}

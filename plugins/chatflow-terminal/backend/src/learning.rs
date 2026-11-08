//! CT's own learning loop. Journals are evidence; checkpoints, snapshots, lessons and verdicts
//! live in CT's graph. Stable event keys make retrying a pass safe, including after a hot swap.
//! Scores are derived from feedback nodes, rather than non-idempotent counter increments.

use crate::{context, flow::Flow, replay, security};
use cc_protocol::contracts::frame::{JournalEntry, JournalReadResult, SessionListResult, kinds};
use cc_protocol::contracts::memory::{KnowledgeItem, KnowledgeListResult, KnowledgeSearchResult, StreamReadResult, methods as memory};
use cc_protocol::contracts::model::{ChatMessage, ChatParams, ChatResult, Priority, Sampling, Thinking, tags};
use cc_protocol::contracts::{mesh::methods as mesh, now_ms};
use cc_protocol::{RpcError, codes, parse_params};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::sync::Notify;
use tokio_util::sync::CancellationToken;

pub const CONTEXT: &str = "terminal_learning_context";
pub const SNAPSHOT: &str = "terminal_learning_snapshot";
pub const BINDING: &str = "terminal_proposal_run";
pub const OUTCOME: &str = "terminal_proposal_outcome";
/// One record per episode: the model request it was answered from and the memory shown in it.
const EPISODES: &str = "terminal.episodes";
const MAX_BACKLOG: usize = 8;
const MAX_LESSONS: usize = 4;
const MAX_FACTS: usize = 4;
const MAX_PREFERENCES: usize = 4;
/// A pass that fails this often is set aside, so one bad episode cannot stall the rest.
pub const MAX_ATTEMPTS: u64 = 3;
/// After this, nothing can change an episode any more: its correction (30 min), its outcome (10
/// min after the proposal) and the rerun of what failed (10 min after that) are all in.
const SETTLE_MS: u64 = 40 * 60 * 1000;
/// A rerun of the failing command proves a fix made by another program within this time.
const RERUN_MS: u64 = 10 * 60 * 1000;

pub struct Learner {
    wake: Notify,
    stop: CancellationToken,
}

impl Learner {
    pub fn start(flow: Weak<Flow>) -> Arc<Self> {
        let learner = Arc::new(Self { wake: Notify::new(), stop: CancellationToken::new() });
        let task = learner.clone();
        tokio::spawn(async move {
            // Activation must finish before the first RPC. The timer also retries failed writes
            // and recovers a command outcome whose event arrived while this plugin was down.
            let mut migrated = false;
            loop {
                tokio::select! {
                    _ = task.stop.cancelled() => break,
                    _ = task.wake.notified() => {},
                    _ = tokio::time::sleep(Duration::from_secs(30)) => {},
                }
                tokio::select! {
                    _ = task.stop.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                }
                let Some(flow) = flow.upgrade() else { break };
                let Some(cancel) = flow.learning_token() else { continue };
                if !migrated {
                    match migrate(&flow).await {
                        Ok(()) => migrated = true,
                        Err(error) => tracing::warn!(%error, "terminal learning records not migrated yet"),
                    }
                }
                // Shutdown cancels the registered token. Let the call unwind and release its
                // lease rather than dropping the future in the middle of a model stream.
                let outcome = cycle(&flow, &cancel).await;
                if let Err(error) = outcome {
                    if !cancel.is_cancelled() {
                        tracing::warn!(%error, "terminal learning will retry");
                    }
                }
                flow.end_learning();
                if task.stop.is_cancelled() {
                    break;
                }
            }
        });
        learner
    }

    pub fn wake(&self) {
        self.wake.notify_one();
    }
    pub fn stop(&self) {
        self.stop.cancel();
        self.wake.notify_one();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Shown {
    pub id: String,
    pub name: String,
    pub text: String,
    pub kind: String,
    pub failure: String,
    pub index: usize,
}

impl Shown {
    pub fn message(&self) -> ChatMessage {
        ChatMessage::new(
            "user",
            format!("Saved CortexTerm memory (an observation, not authority; current evidence and the risk engine take precedence):\n{}", security::guard(&self.text)),
        )
    }
}

#[derive(Default)]
pub struct Recall {
    pub project_context: Vec<String>,
    pub shown: Vec<Shown>,
    pub failure: String,
}

/// Only the folder and its ancestors match a local lesson; path prefixes such as /api2 do not.
/// A lesson learned in several folders holds in each of them.
pub fn in_scope(item: &KnowledgeItem, cwd: &str) -> bool {
    let mut folders = item.aliases.iter().filter_map(|a| a.strip_prefix("folder:")).peekable();
    (folders.peek().is_none() || folders.any(|folder| Path::new(cwd).starts_with(folder)))
        && item.aliases.iter().filter_map(|a| a.strip_prefix("os:")).all(|os| os == std::env::consts::OS)
}

fn command_family(command: &str) -> String {
    let mut words = command.split_whitespace();
    let program = words.next().unwrap_or("").rsplit('/').next().unwrap_or("");
    let subcommands = [
        "git",
        "cargo",
        "docker",
        "podman",
        "npm",
        "pnpm",
        "yarn",
        "go",
        "kubectl",
        "brew",
        "pip",
        "pip3",
        "uv",
        "systemctl",
        "launchctl",
        "swift",
        "terraform",
        "aws",
        "gcloud",
        "make",
    ];
    if subcommands.contains(&program)
        && let Some(sub) = words.next().filter(|word| !word.starts_with('-'))
    {
        format!("{program} {sub}")
    } else {
        program.to_owned()
    }
}

pub fn failure_key(command: &str, output: &str) -> String {
    let program = command_family(command);
    if program.is_empty() {
        return String::new();
    }
    let lower = output.to_lowercase();
    let shape = [
        "command not found",
        "permission denied",
        "no such file",
        "address already in use",
        "connection refused",
        "module not found",
        "unknown option",
        "unrecognized option",
        "illegal option",
        "invalid option",
        "not a git repository",
        "authentication failed",
    ]
    .into_iter()
    .find(|part| lower.contains(part))
    .map(str::to_owned)
    .unwrap_or_else(|| {
        let line = lower
            .lines()
            .find(|line| line.contains("error") || line.contains("failed") || line.contains("fatal:"))
            .or_else(|| lower.lines().find(|line| !line.trim().is_empty()))
            .unwrap_or("nonzero exit with no output");
        line.split_whitespace().map(|word| if word.contains('/') || word.chars().any(|c| c.is_ascii_digit()) { "_" } else { word }).collect::<Vec<_>>().join(" ")
    });
    if shape.is_empty() { String::new() } else { format!("failed {program} {}", cut(&shape, 160)) }
}

pub async fn recall(flow: &Flow, question: &str, cwd: &str, failed_id: Option<&str>, project_context: &[String]) -> Result<Recall, RpcError> {
    let mut recalled = Recall { project_context: project_context.to_vec(), ..Recall::default() };
    if let Some(id) = failed_id {
        let mut run: Option<(String, i64)> = rows(flow, "MATCH (r:CommandRun {key: $id}) RETURN r.command, r.exit_code", json!({"id": id}), 1)
            .await?
            .first()
            .and_then(|row| Some((row.first()?.as_str()?.to_owned(), row.get(1)?.as_i64()?)));
        // A Run that just finished may still wait in the terminal's outbox: the terminal has it.
        if run.is_none()
            && let Ok(list) = flow.ctx()?.call("terminal.runs", json!({"failed_only": true, "limit": 50})).await
        {
            run = list["runs"].as_array().into_iter().flatten().find(|r| r["id"] == id).and_then(|r| Some((r["command"].as_str()?.to_owned(), r["exit_code"].as_i64()?)));
        }
        if let Some((command, code)) = run
            && code != 0
            && let Ok(output) = flow.ctx()?.call("terminal.run.output", json!({"run_id": id, "from": -60, "count": 60})).await
        {
            recalled.failure = failure_key(&command, &output_text(&output));
        }
    }
    let facts: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "fact"})).await?)?;
    // The nearest folder's facts first (this folder's before its parents'), newest first within it.
    let mut places: Vec<(usize, &KnowledgeItem)> = facts
        .items
        .iter()
        .filter_map(|item| {
            let (folder, _) = item.name.strip_prefix("place ")?.split_once(": ")?;
            (Path::new(cwd).starts_with(folder) && in_scope(item, cwd) && security::guarded_reasons(&item.text).is_none()).then_some((folder.len(), item))
        })
        .collect();
    places.sort_by(|a, b| b.0.cmp(&a.0).then(b.1.updated_ms.cmp(&a.1.updated_ms)));
    for (_, item) in places.into_iter().take(MAX_FACTS) {
        recalled.shown.push(shown(item, "", None));
    }
    let scores = match scores(flow).await {
        Ok(scores) => scores,
        Err(error) => {
            tracing::debug!(%error, "lesson scores unavailable; using folder facts only");
            return Ok(recalled);
        }
    };
    let usable = |item: &KnowledgeItem| in_scope(item, cwd) && security::guarded_reasons(&item.text).is_none() && !harmful(scores.get(&item.id));
    let lessons: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson"})).await?)?;
    // A standing preference holds whatever the question is about. The pass that distilled a
    // lesson says what it is anchored to.
    let preferences: HashSet<String> = rows(flow, "MATCH (p:TerminalLearningPass {anchor: 'preference'})-[:DISTILLED]->(k:Knowledge) RETURN DISTINCT k.id", json!({}), 5000)
        .await?
        .into_iter()
        .filter_map(|row| row.first()?.as_str().map(str::to_owned))
        .collect();
    for item in lessons.items.iter().filter(|item| preferences.contains(&item.id) && usable(item)).take(MAX_PREFERENCES) {
        recalled.shown.push(shown(item, "", None));
    }
    let mut candidates: HashMap<String, KnowledgeItem> = HashMap::new();
    // The question, with what failed: an automatic fix turn's question says little by itself.
    let query = if recalled.failure.is_empty() { cut(question, 1000) } else { format!("{}\n{}", cut(question, 800), recalled.failure) };
    let searched = flow.ctx()?.call(memory::KNOWLEDGE_SEARCH, json!({"text": query, "kind": "lesson", "limit": 16})).await;
    match searched.and_then(parse_params::<KnowledgeSearchResult>) {
        Ok(searched) => {
            for item in searched.items.into_iter().filter(|item| item.score.unwrap_or(0.0) >= 0.35 && usable(item)) {
                candidates.insert(item.id.clone(), item);
            }
        }
        Err(error) => tracing::debug!(%error, "meaning search unavailable; folder facts and failure-key recall remain available"),
    }
    if !recalled.failure.is_empty() {
        for mut item in lessons.items.into_iter().filter(|item| item.aliases.contains(&recalled.failure) && usable(item)) {
            item.score = Some(2.0);
            candidates.insert(item.id.clone(), item);
        }
    }
    let mut candidates: Vec<_> = candidates.into_values().filter(|item| !recalled.shown.iter().any(|shown| shown.id == item.id)).collect();
    candidates.sort_by(|a, b| {
        let rank = |item: &KnowledgeItem| item.score.unwrap_or(0.0) + scores.get(&item.id).map_or(0.0, |s| 0.05 * (s.helped.min(5) as f64 - s.hurt.min(5) as f64));
        rank(b).total_cmp(&rank(a)).then_with(|| a.id.cmp(&b.id))
    });
    for item in candidates.into_iter().take(MAX_LESSONS) {
        let key = if item.aliases.contains(&recalled.failure) { &recalled.failure } else { "" };
        recalled.shown.push(shown(&item, key, Some(project_context)));
    }
    Ok(recalled)
}

/// Failure-key recall happens immediately after a failed check, once per item per turn.
pub async fn at_failure(flow: &Flow, key: &str, cwd: &str, already: &[Shown], project_context: &[String]) -> Result<Vec<Shown>, RpcError> {
    let listed: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson"})).await?)?;
    let scores = scores(flow).await?;
    Ok(listed
        .items
        .iter()
        .filter(|item| {
            item.aliases.iter().any(|alias| alias == key)
                && in_scope(item, cwd)
                && security::guarded_reasons(&item.text).is_none()
                && !already.iter().any(|shown| shown.id == item.id)
                && !harmful(scores.get(&item.id))
        })
        .take(2)
        .map(|item| shown(item, key, Some(project_context)))
        .collect())
}

/// A memory item as the model sees it, with how old it is (old memory may no longer hold).
pub(crate) fn shown(item: &KnowledgeItem, failure: &str, project_context: Option<&[String]>) -> Shown {
    let text = match age(item.updated_ms) {
        Some(age) => format!("{} (saved {age})", cut(&item.text, 580)),
        None => cut(&item.text, 600),
    };
    let text = match project_context {
        Some(observed) if item.kind == "lesson" => format!("{}\n{text}", context::notice(&item.aliases, observed)),
        _ => text,
    };
    Shown { id: item.id.clone(), name: item.name.clone(), text, kind: item.kind.clone(), failure: failure.into(), index: 0 }
}

/// "today", "yesterday", "5 days ago", "3 months ago".
pub fn age(at_ms: u64) -> Option<String> {
    if at_ms == 0 {
        return None;
    }
    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0);
    let days = now.saturating_sub(at_ms) / 86_400_000;
    Some(match days {
        0 => "today".into(),
        1 => "yesterday".into(),
        2..=59 => format!("{days} days ago"),
        _ => format!("{} months ago", days / 30),
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    pub session: String,
    pub run: String,
    pub seq: u64,
    pub ts_ms: u64,
    pub question: String,
    /// The automatic follow-up to a command the user ran, not their own words.
    pub continuing: bool,
    pub intent: String,
    pub cwd: String,
    pub term_id: String,
    pub failure: String,
    pub answer: String,
    pub proposal: String,
    pub proposal_ms: u64,
    pub facts: String,
    #[serde(default)]
    pub project_context: Vec<String>,
    pub status: String,
    pub messages: Vec<ChatMessage>,
    pub shown: Vec<Shown>,
    pub checks: String,
    pub outcome_id: String,
    pub outcome_command: String,
    pub outcome_exit: Option<i64>,
    pub outcome_failure: String,
    /// The command that failed passed again soon after the outcome (a fix by another program).
    pub rerun_ok: bool,
    pub check_repair: bool,
    pub correction: String,
    pub correction_seq: u64,
}

impl Episode {
    pub fn key(&self) -> String {
        format!("{}/{}", self.session, self.run)
    }
    fn revision(&self) -> String {
        let rerun = if self.rerun_ok { "/rerun" } else { "" };
        format!("{}/{}/{}/{}{rerun}", self.key(), self.outcome_id, self.outcome_exit.map_or("pending".into(), |c| c.to_string()), self.correction_seq)
    }
    pub fn verified_fix(&self) -> bool {
        let program = command_family(&self.outcome_command);
        self.outcome_exit == Some(0) && !program.is_empty() && (self.rerun_ok || self.failure.starts_with(&format!("failed {program} ")))
    }
    /// Nothing can change it any more.
    fn ripe(&self) -> bool {
        now_ms().saturating_sub(self.ts_ms.max(self.proposal_ms)) >= SETTLE_MS
    }
}

/// Serial passes are bounded so a large history cannot monopolize the shared model. Each session
/// keeps where its settled episodes end, and, once all are settled, the journal revision: a
/// journal unchanged since is not read again.
async fn cycle(flow: &Flow, cancel: &CancellationToken) -> Result<(), RpcError> {
    let listed: SessionListResult = parse_params(flow.ctx()?.call("frame.session.list", json!({})).await?)?;
    let mut sessions: Vec<_> = listed.sessions.into_iter().filter(|s| s.flow == "terminal").collect();
    sessions.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms));
    let mut taken = 0;
    for session in sessions {
        check_cancel(cancel)?;
        let mark = rows(flow, "MATCH (s:TerminalLearningSession {key: $key}) RETURN s.rev, s.settled_seq", json!({"key": session.id}), 1).await?;
        let settled_seq = mark.first().and_then(|r| r.get(1)).and_then(Value::as_u64).unwrap_or(0);
        if let Some(rev) = mark.first().and_then(|r| r.first()).and_then(Value::as_u64) {
            let head: JournalReadResult = parse_params(flow.ctx()?.call("frame.journal.read", json!({"session_id": session.id, "from": u64::MAX})).await?)?;
            if head.rev == rev {
                continue;
            }
        }
        let read: JournalReadResult = parse_params(flow.ctx()?.call("frame.journal.read", json!({"session_id": session.id})).await?)?;
        let mut seen = HashSet::new();
        // The earliest episode that can still change.
        let mut open = u64::MAX;
        for entry in read.entries.iter().rev().filter(|e| e.seq > settled_seq && e.kind == kinds::STATUS && matches!(field(&e.data, "state"), "done" | "failed" | "cancelled")) {
            let run = field(&entry.data, "run_id");
            if run.is_empty() || !seen.insert(run.to_owned()) {
                continue;
            }
            let Some(mut episode) = episode(&session.id, run, &read.entries) else { continue };
            resolve_outcome(flow, &mut episode, &read.entries).await?;
            let key = episode.key();
            let revision = episode.revision();
            let pass = rows(flow, "MATCH (p:TerminalLearningPass {key: $key}) RETURN p.state, p.attempts", json!({"key": revision}), 1).await?;
            let state = pass.first().and_then(|r| r.first()).and_then(Value::as_str).unwrap_or("");
            let attempts = pass.first().and_then(|r| r.get(1)).and_then(Value::as_u64).unwrap_or(0);
            if !episode.ripe() {
                open = open.min(entry.seq);
            }
            if state == "done" || attempts >= MAX_ATTEMPTS {
                continue;
            }
            open = open.min(entry.seq);
            check_cancel(cancel)?;
            let learned = async {
                persist_episode(flow, &episode).await?;
                learn_episode(flow, &episode, cancel).await
            }
            .await;
            match learned {
                Ok(()) => tracing::debug!(episode = %key, "terminal learning pass kept"),
                Err(error) if error.code == codes::CANCELLED || cancel.is_cancelled() => return Err(error),
                Err(error) => {
                    // Kept with its count; the next cycle goes on to the other episodes.
                    tracing::warn!(episode = %key, %error, attempt = attempts + 1, "terminal learning pass failed");
                    put(
                        flow,
                        vec![json!({"label": "TerminalLearningPass", "key": revision, "props": {"state": "failed", "attempts": attempts + 1, "error": cut(&error.message, 300), "updated_ms": now_ms()}})],
                        vec![edge("TerminalLearningPass", &revision, "FROM", "TerminalEpisode", &key)],
                    )
                    .await?;
                }
            }
            taken += 1;
            if taken >= MAX_BACKLOG {
                settle_lessons(flow).await?;
                flow.wake_learning();
                return Ok(());
            }
        }
        let props = if open == u64::MAX {
            json!({"settled_seq": read.entries.last().map_or(0, |e| e.seq), "rev": read.rev})
        } else {
            json!({"settled_seq": open - 1})
        };
        put(flow, vec![json!({"label": "TerminalLearningSession", "key": session.id, "props": props})], vec![edge("TerminalLearningSession", &session.id, "OF", "Session", &session.id)]).await?;
    }
    check_cancel(cancel)?;
    settle_lessons(flow).await?;
    replay::one(flow, cancel).await
}

fn episode(session: &str, run: &str, entries: &[JournalEntry]) -> Option<Episode> {
    let mine: Vec<_> = entries.iter().filter(|e| field(&e.data, "run_id") == run).collect();
    let user = mine.iter().find(|e| e.kind == kinds::USER_MESSAGE)?;
    let context = mine.iter().find(|e| field(&e.data, "purpose") == CONTEXT).map(|e| &e.data);
    let snapshot = mine.iter().rev().find(|e| field(&e.data, "purpose") == SNAPSHOT).map(|e| &e.data);
    let value = |name| context.and_then(|d| d.get(name)).cloned().unwrap_or(Value::Null);
    let status = mine.iter().rev().find(|e| e.kind == kinds::STATUS).map(|e| field(&e.data, "state")).unwrap_or("");
    let proposal = mine.iter().rev().find(|e| e.kind == "command_proposal").map(|e| field(&e.data, "command")).unwrap_or("");
    let next = entries.iter().find(|e| {
        e.seq > user.seq
            && e.kind == kinds::USER_MESSAGE
            && field(&e.data, "run_id") != run
            && field(&e.data, "term_id") == field(&user.data, "term_id")
            && e.data.get("automatic").and_then(Value::as_bool) != Some(true)
            && e.data.get("continuing").and_then(Value::as_bool) != Some(true)
            && e.ts_ms.saturating_sub(user.ts_ms) < 30 * 60 * 1000
    });
    let check_repair = mine.iter().enumerate().any(|(i, failed)| {
        let refused = failed.data.get("refused").and_then(Value::as_bool) == Some(true);
        let key = if refused { "refused run".into() } else { failure_key(field(&failed.data, "command"), field(&failed.data, "output")) };
        failed.kind == "command_step"
            && (refused || failed.data.get("exit_code").and_then(Value::as_i64).is_some_and(|code| code != 0))
            && context.is_some_and(|d| field(d, "failure") == key)
            && mine[i + 1..].iter().any(|later| {
                later.kind == "command_step"
                    && later.data.get("exit_code").and_then(Value::as_i64) == Some(0)
                    && !field(&failed.data, "command").is_empty()
                    && if refused { field(&later.data, "tool") == "run" } else { command_family(field(&later.data, "command")) == command_family(field(&failed.data, "command")) }
            })
    });
    Some(Episode {
        session: session.into(),
        run: run.into(),
        seq: user.seq,
        ts_ms: user.ts_ms,
        question: cut(field(&user.data, "text"), 3000),
        continuing: user.data.get("continuing").and_then(Value::as_bool) == Some(true),
        intent: field(&user.data, "intent").into(),
        cwd: folder_key(value("cwd").as_str().unwrap_or("")),
        term_id: field(&user.data, "term_id").into(),
        failure: value("failure").as_str().unwrap_or("").into(),
        answer: cut(mine.iter().rev().find(|e| e.kind == kinds::ASSISTANT_MESSAGE).map(|e| field(&e.data, "text")).unwrap_or(""), 4000),
        proposal: proposal.into(),
        status: status.into(),
        proposal_ms: mine.iter().rev().find(|e| e.kind == "command_proposal").map_or(0, |e| e.ts_ms),
        facts: value("facts").as_str().unwrap_or("").to_owned(),
        project_context: serde_json::from_value(value("project_context")).unwrap_or_default(),
        messages: snapshot.and_then(|d| d.get("messages")).and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default(),
        shown: context.and_then(|d| d.get("shown")).and_then(|v| serde_json::from_value(v.clone()).ok()).unwrap_or_default(),
        checks: cut(
            &mine
                .iter()
                .filter(|e| e.kind == "command_step")
                .map(|e| format!("{} (exit {:?}):\n{}", field(&e.data, "command"), e.data.get("exit_code"), field(&e.data, "output")))
                .collect::<Vec<_>>()
                .join("\n"),
            6000,
        ),
        outcome_id: String::new(),
        outcome_command: String::new(),
        outcome_exit: None,
        outcome_failure: String::new(),
        rerun_ok: false,
        check_repair,
        correction: next.map(|e| cut(field(&e.data, "text"), 2000)).unwrap_or_default(),
        correction_seq: next.map_or(0, |e| e.seq),
    })
}

async fn resolve_outcome(flow: &Flow, episode: &mut Episode, entries: &[JournalEntry]) -> Result<(), RpcError> {
    if episode.proposal.is_empty() {
        return Ok(());
    }
    let binding = entries
        .iter()
        .rev()
        .find(|e| field(&e.data, "run_id") == episode.run && field(&e.data, "purpose") == OUTCOME)
        .or_else(|| entries.iter().rev().find(|e| field(&e.data, "run_id") == episode.run && field(&e.data, "purpose") == BINDING));
    if let Some(binding) = binding {
        episode.outcome_id = field(&binding.data, "command_id").into();
        // Prefer durable Run data below. The event also covers the store's short batching delay.
        if field(&binding.data, "purpose") == OUTCOME {
            episode.outcome_command = field(&binding.data, "command").into();
            episode.outcome_exit = binding.data.get("exit_code").and_then(Value::as_i64);
        }
    }
    if episode.outcome_id.is_empty() && !episode.term_id.is_empty() && episode.proposal_ms > 0 {
        // A hot swap loses the in-memory follow-up, but not the proposal or command history.
        // Recover the first command after the proposal, bounded by the next manual request.
        let until = entries
            .iter()
            .find(|e| {
                e.seq > episode.seq
                    && e.kind == kinds::USER_MESSAGE
                    && field(&e.data, "term_id") == episode.term_id
                    && e.data.get("continuing").and_then(Value::as_bool) != Some(true)
            })
            .map_or(episode.proposal_ms + 600_000, |e| e.ts_ms.min(episode.proposal_ms + 600_000));
        let found = rows(
            flow,
            "MATCH (r:CommandRun)-[:IN_SHELL]->(s:Shell {key: $shell}) WHERE r.started_ms >= $after AND r.started_ms <= $until RETURN r.key ORDER BY r.started_ms LIMIT 1",
            json!({"shell": episode.term_id, "after": episode.proposal_ms, "until": until}),
            1,
        )
        .await?;
        if let Some(id) = found.first().and_then(|row| row.first()).and_then(Value::as_str) {
            episode.outcome_id = id.into();
        }
    }
    let mut outcome_ms = 0;
    if !episode.outcome_id.is_empty() {
        let found = rows(flow, "MATCH (r:CommandRun {key: $id}) RETURN r.command, r.exit_code, r.started_ms", json!({"id": episode.outcome_id}), 1).await?;
        if let Some(row) = found.first() {
            episode.outcome_command = row.first().and_then(Value::as_str).unwrap_or("").into();
            episode.outcome_exit = row.get(1).and_then(Value::as_i64).or(episode.outcome_exit);
            outcome_ms = row.get(2).and_then(Value::as_u64).unwrap_or(0);
        }
    }
    // A Run recorded on another machine has no output here: the outcome stays without its key.
    if episode.outcome_exit.is_some_and(|code| code != 0)
        && !episode.outcome_id.is_empty()
        && let Ok(output) = flow.ctx()?.call("terminal.run.output", json!({"run_id": episode.outcome_id, "from": -60, "count": 60})).await
    {
        episode.outcome_failure = failure_key(&episode.outcome_command, &output_text(&output));
    }
    // A fix by another program (`brew install openssl` for a failing `cargo build`) is proven
    // when the next run of the failing program, soon after, passes.
    let program = command_family(&episode.outcome_command);
    if episode.outcome_exit == Some(0) && outcome_ms > 0 && episode.failure.starts_with("failed ") && !episode.failure.starts_with(&format!("failed {program} ")) {
        let later = rows(
            flow,
            "MATCH (r:CommandRun)-[:IN_SHELL]->(s:Shell {key: $shell}) WHERE r.started_ms > $after AND r.started_ms <= $until RETURN r.command, r.exit_code ORDER BY r.started_ms LIMIT 50",
            json!({"shell": episode.term_id, "after": outcome_ms, "until": outcome_ms + RERUN_MS}),
            50,
        )
        .await?;
        let rerun = later.iter().find(|row| {
            let family = command_family(row.first().and_then(Value::as_str).unwrap_or(""));
            !family.is_empty() && episode.failure.starts_with(&format!("failed {family} "))
        });
        episode.rerun_ok = rerun.is_some_and(|row| row.get(1).and_then(Value::as_i64) == Some(0));
    }
    Ok(())
}

/// The episode's facts and edges. Its request snapshot is a record of that moment: appended once
/// to the episodes stream, found again from the episode's `at_ms`.
pub async fn persist_episode(flow: &Flow, e: &Episode) -> Result<(), RpcError> {
    let key = e.key();
    let written = rows(flow, "MATCH (e:TerminalEpisode {key: $key}) RETURN e.at_ms", json!({"key": key}), 1).await?;
    let at_ms = match written.first().and_then(|r| r.first()).and_then(Value::as_u64) {
        Some(at_ms) => at_ms,
        None => {
            let at_ms = now_ms();
            append_episodes(flow, vec![json!({"episode": key, "messages": e.messages, "shown": e.shown})]).await?;
            at_ms
        }
    };
    let mut nodes = vec![json!({"label": "TerminalEpisode", "key": key, "props": {
        "source_seq": e.seq, "created_ms": e.ts_ms, "at_ms": at_ms,
        "question": e.question, "intent": e.intent, "failure": e.failure,
        "answer": e.answer, "proposal": e.proposal, "proposal_ms": e.proposal_ms, "facts": e.facts, "status": e.status,
        "project_context": e.project_context, "checks": e.checks, "outcome_exit": e.outcome_exit, "outcome_failure": e.outcome_failure, "rerun_ok": e.rerun_ok,
        "verified_fix": e.verified_fix(), "check_repair": e.check_repair, "correction": e.correction, "correction_seq": e.correction_seq
    }})];
    let mut edges = vec![edge("TerminalEpisode", &key, "OF", "Session", &e.session)];
    if !e.cwd.is_empty() {
        folder_chain(&e.cwd, &mut nodes, &mut edges);
        edges.push(edge("TerminalEpisode", &key, "ABOUT", "Folder", &e.cwd));
    }
    for item in &e.shown {
        edges.push(edge("TerminalEpisode", &key, "SHOWN", "Knowledge", &item.id));
    }
    // CommandRun is independently owned by the terminal store; do not create a placeholder Run.
    if !e.outcome_id.is_empty() {
        let exists = rows(flow, "MATCH (r:CommandRun {key: $key}) RETURN r.key", json!({"key": e.outcome_id}), 1).await?;
        if !exists.is_empty() {
            edges.push(edge("TerminalEpisode", &key, "OBSERVED", "CommandRun", &e.outcome_id));
        }
    }
    put(flow, nodes, edges).await
}

async fn append_episodes(flow: &Flow, records: Vec<Value>) -> Result<(), RpcError> {
    flow.ctx()?.call(memory::STREAM_APPEND, json!({"topic": EPISODES, "records": records, "retention_days": 365})).await.map(|_| ())
}

/// The request snapshot and shown memory of an episode, from its record in the episodes stream.
pub async fn episode_record(flow: &Flow, episode: &str, at_ms: u64) -> Result<Option<(Vec<ChatMessage>, Vec<Shown>)>, RpcError> {
    let mut from = None;
    loop {
        let page: StreamReadResult = parse_params(flow.ctx()?.call(memory::STREAM_READ, json!({"topic": EPISODES, "since_ms": at_ms, "from_offset": from, "limit": 500})).await?)?;
        if let Some(record) = page.records.iter().find(|r| field(&r.value, "episode") == episode) {
            let messages = serde_json::from_value(record.value.get("messages").cloned().unwrap_or_default())?;
            let shown = serde_json::from_value(record.value.get("shown").cloned().unwrap_or_default())?;
            return Ok(Some((messages, shown)));
        }
        if page.end || page.records.is_empty() {
            return Ok(None);
        }
        from = Some(page.next_offset);
    }
}

/// A folder as the terminal keys it: absolute, without a trailing `/` (`/` itself stays); empty
/// when it is not absolute.
fn folder_key(cwd: &str) -> String {
    match cwd.trim_end_matches('/') {
        _ if !cwd.starts_with('/') => String::new(),
        "" => "/".into(),
        trimmed => trimmed.into(),
    }
}

/// The folder and the folders above it, linked by IN, up to the home folder for one below it,
/// else up to `/`: the same Folder nodes the terminal writes.
fn folder_chain(folder: &str, nodes: &mut Vec<Value>, edges: &mut Vec<Value>) {
    let home = std::env::var("HOME").unwrap_or_default();
    let mut below: Option<String> = None;
    for dir in Path::new(folder).ancestors() {
        let dir = dir.to_string_lossy().into_owned();
        nodes.push(json!({"label": "Folder", "key": dir}));
        if let Some(child) = below.replace(dir.clone()) {
            edges.push(edge("Folder", &child, "IN", "Folder", &dir));
        }
        if dir == home.trim_end_matches('/') || dir == "/" {
            break;
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Distilled {
    useful: String,
    lesson: String,
    anchor: String,
    scope: String,
    correction_quote: String,
    /// Checkpoints written before this field existed have none.
    #[serde(default)]
    preference_quote: String,
    contradicted: Vec<String>,
}

async fn learn_episode(flow: &Flow, e: &Episode, cancel: &CancellationToken) -> Result<(), RpcError> {
    let pass_key = e.revision();
    let prior = rows(
        flow,
        "MATCH (p:TerminalLearningPass {key: $key}) WHERE p.useful IS NOT NULL OPTIONAL MATCH (p)-[:CONTRADICTED]->(k:Knowledge) \
         RETURN p.useful, p.lesson, p.anchor, p.scope, p.correction_quote, p.preference_quote, collect(k.id)",
        json!({"key": pass_key}),
        1,
    )
    .await?;
    let lesson: Option<Distilled> = if let Some(row) = prior.first() {
        let text = |index: usize| row.get(index).and_then(Value::as_str).unwrap_or("").to_owned();
        let contradicted = row.get(6).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
        Some(Distilled { useful: text(0), lesson: text(1), anchor: text(2), scope: text(3), correction_quote: text(4), preference_quote: text(5), contradicted })
    } else if e.status != "cancelled" && (!e.continuing || !e.failure.is_empty() || e.outcome_exit.is_some_and(|code| code != 0) || !e.correction.is_empty() || e.checks.contains("Not run:")) {
        let schema: Value = serde_json::from_str(&std::fs::read_to_string(flow.data_file("schemas/learn.json")).map_err(|error| RpcError::internal(error.to_string()))?)?;
        let card = json!({"question": e.question, "intent": e.intent, "folder": e.cwd, "failure": e.failure, "facts": e.facts, "checks": e.checks,
            "answer": e.answer, "proposal": e.proposal, "observed_command": e.outcome_command, "observed_exit": e.outcome_exit, "verified_fix": e.verified_fix(), "check_repair": e.check_repair,
            "next_user_message": e.correction, "question_is_user_words": !e.continuing, "shown": e.shown});
        let result =
            background(flow, "learn", vec![ChatMessage::new("system", flow.prompt("learn")?), ChatMessage::new("user", security::guard(&card.to_string()))], Some(schema), cancel)
                .await?;
        if result.result.finish_reason != "stop" {
            return Err(RpcError::internal("terminal lesson extraction did not finish"));
        }
        let mut learned: Distilled = parse_json(&result.result.content)?;
        // Only memory shown in the episode can have been contradicted by it.
        learned.contradicted.retain(|id| e.shown.iter().any(|shown| &shown.id == id));
        Some(learned)
    } else {
        None
    };
    check_cancel(cancel)?;
    // Persist the actual extraction before any side effect, so a retry does not ask for a new lesson.
    pass(flow, e, &pass_key, "distilled", lesson.as_ref(), None).await?;
    let mut lesson_id = None;
    if let Some(learned) = &lesson {
        let text = learned.lesson.split_whitespace().collect::<Vec<_>>().join(" ");
        let anchor_ok = matches!(learned.anchor.as_str(), "tool:run" | "tool:skill" | "approach" | "preference") || learned.anchor.starts_with("command:");
        // A model may propose a lesson, never relax the command risk policy through memory.
        let explicit_correction = was_corrected(learned, e);
        // The user's own standing rule, in their own words ("I use pnpm here", "remember ...").
        let stated = !e.continuing && !learned.preference_quote.trim().is_empty() && e.question.contains(&learned.preference_quote);
        // Why it is kept, as Settings › Memory says it.
        let why = if e.verified_fix() {
            Some("fix")
        } else if e.check_repair {
            Some("check")
        } else if explicit_correction {
            Some("correction")
        } else if stated {
            Some("preference")
        } else {
            None
        };
        if let Some(why) = why
            && learned.useful == "yes"
            && !text.is_empty()
            && text.chars().count() <= 240
            && anchor_ok
            && security::guarded_reasons(&text).is_none()
        {
            lesson_id = keep(flow, e, learned, &text, why).await?;
        }
        if explicit_correction {
            replace_corrected(flow, e, learned, lesson_id.as_deref()).await?;
        }
    }
    feedback(flow, e, lesson.as_ref()).await?;
    check_cancel(cancel)?;
    pass(flow, e, &pass_key, "done", lesson.as_ref(), lesson_id.as_deref()).await?;
    Ok(())
}

fn was_corrected(learned: &Distilled, e: &Episode) -> bool {
    !learned.correction_quote.trim().is_empty() && e.correction.contains(&learned.correction_quote)
}

/// The user said a shown lesson was wrong: it goes now, replaced by what they said instead when
/// that was learned, rather than waiting for three bad observations.
async fn replace_corrected(flow: &Flow, e: &Episode, learned: &Distilled, replacement: Option<&str>) -> Result<(), RpcError> {
    for id in learned.contradicted.iter().filter(|id| e.shown.iter().any(|shown| &shown.id == *id && shown.kind == "lesson")) {
        let item: KnowledgeItem = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_GET, json!({"id": id})).await?)?;
        if item.by != "chatflow-terminal" || matches!(item.state.as_str(), "withdrawn" | "superseded") {
            continue;
        }
        match replacement.filter(|new| new != id) {
            Some(new) => flow.ctx()?.call(memory::KNOWLEDGE_SUPERSEDE, json!({"id": id, "by": new})).await?,
            None => flow.ctx()?.call(memory::KNOWLEDGE_WITHDRAW, json!({"id": id, "reason": "The user corrected it", "by": "chatflow-terminal"})).await?,
        };
    }
    Ok(())
}

/// The pass's state and what the model distilled: its fields, the shown memory it contradicted
/// and the lesson kept from it.
async fn pass(flow: &Flow, e: &Episode, key: &str, state: &str, distilled: Option<&Distilled>, kept: Option<&str>) -> Result<(), RpcError> {
    let props = match distilled {
        Some(d) => json!({"state": state, "updated_ms": now_ms(), "useful": d.useful, "lesson": d.lesson, "anchor": d.anchor, "scope": d.scope,
            "correction_quote": d.correction_quote, "preference_quote": d.preference_quote}),
        None => json!({"state": state, "updated_ms": now_ms()}),
    };
    let mut edges = vec![edge("TerminalLearningPass", key, "FROM", "TerminalEpisode", &e.key())];
    if let Some(d) = distilled {
        edges.extend(d.contradicted.iter().map(|id| edge("TerminalLearningPass", key, "CONTRADICTED", "Knowledge", id)));
    }
    if let Some(id) = kept {
        edges.push(edge("TerminalLearningPass", key, "DISTILLED", "Knowledge", id));
    }
    put(flow, vec![json!({"label": "TerminalLearningPass", "key": key, "props": props})], edges).await
}

async fn keep(flow: &Flow, e: &Episode, learned: &Distilled, text: &str, why: &str) -> Result<Option<String>, RpcError> {
    let local = learned.scope != "general" || text.contains('/') || text.contains('~') || (!e.cwd.is_empty() && text.contains(&e.cwd));
    if local && e.cwd.is_empty() {
        return Ok(None);
    }
    // The lesson is its text. Where it holds is its ABOUT edge and scope alias; what it is anchored
    // to is on the pass that distilled it. The same lesson learned in another folder is one item.
    let scope = if local { format!("folder:{}", e.cwd) } else { format!("os:{}", std::env::consts::OS) };
    let name = text;
    let all: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson", "include_history": true})).await?)?;
    let mut existing = all.items.iter().find(|item| item.name == name).cloned();
    if existing.is_none() {
        // Withdrawn and replaced lessons too: one the user removed is not learned again in other words.
        let similar: KnowledgeSearchResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_SEARCH, json!({"kind": "lesson", "text": text, "limit": 3, "include_history": true})).await?)?;
        existing =
            similar.items.into_iter().find(|item| item.score.unwrap_or(0.0) >= 0.90 && item.aliases.contains(&scope));
    }
    // A user editing a learned item owns it; the learner does not replace that provenance.
    if existing.as_ref().is_some_and(|item| item.by != "chatflow-terminal") {
        return Ok(None);
    }
    if existing.as_ref().is_some_and(|item| matches!(item.state.as_str(), "withdrawn" | "superseded")) {
        return Ok(None);
    }
    let name = existing.as_ref().map(|item| item.name.as_str()).unwrap_or(name);
    let mut aliases = vec![scope];
    // Bind only the episode's most specific observed folder. Parent inputs must not
    // override changed child inputs; user preferences are not software-compatibility claims.
    if why != "preference" && let Some(binding) = e.project_context.first().filter(|binding| context::is_binding(binding)) {
        aliases.push(binding.clone());
    }
    if !e.failure.is_empty() {
        aliases.push(e.failure.clone());
    }
    let item: KnowledgeItem = parse_params(
        flow.ctx()?
            .call(
                memory::KNOWLEDGE_UPSERT,
                json!({
                    "kind": "lesson", "name": name, "text": if existing.is_some() { "" } else { text }, "source": "agent",
                    "confidence": 0.5, "by": "chatflow-terminal", "aliases": aliases,
                    "evidence": [format!("journal://{}/{}", e.session, e.seq)]
                }),
            )
            .await?,
    )?;
    let mut learned_from = edge("Knowledge", &item.id, "LEARNED_FROM", "TerminalEpisode", &e.key());
    learned_from["props"] = json!({"why": why});
    let mut edges = vec![learned_from];
    let mut nodes = Vec::new();
    if local {
        folder_chain(&e.cwd, &mut nodes, &mut edges);
        edges.push(edge("Knowledge", &item.id, "ABOUT", "Folder", &e.cwd));
    }
    put(flow, nodes, edges).await?;
    Ok(Some(item.id))
}

async fn feedback(flow: &Flow, e: &Episode, distilled: Option<&Distilled>) -> Result<(), RpcError> {
    let lessons: Vec<_> = e.shown.iter().filter(|s| s.kind == "lesson").collect();
    let matching = lessons.iter().filter(|s| !s.failure.is_empty() && s.failure == e.failure).count();
    for item in lessons {
        let corrected = distilled.is_some_and(|d| was_corrected(d, e) && d.contradicted.contains(&item.id));
        let applied = !e.proposal.is_empty() && replay::same_command(&e.proposal, &e.outcome_command);
        let verdict = if corrected {
            "hurt"
        } else if applied && !item.failure.is_empty() && item.failure == e.outcome_failure {
            "hurt"
        } else if ((applied && e.verified_fix()) || e.check_repair) && item.failure == e.failure && !e.failure.is_empty() {
            if matching == 1 { "helped" } else { "confounded" }
        } else {
            "no_observed_effect"
        };
        // An unanswered proposal is not a success. Command and correction observations have their
        // own keys; reprocessing another revision cannot increment the same evidence twice.
        let observation = if corrected {
            format!("correction-{}", e.correction_seq)
        } else if !e.outcome_id.is_empty() && e.outcome_exit.is_some() {
            format!("command-{}", e.outcome_id)
        } else if e.check_repair {
            "checks".into()
        } else {
            "turn".into()
        };
        let key = format!("{}/{}/{}", e.key(), item.id, observation);
        record_feedback(
            flow,
            &key,
            &e.key(),
            &item.id,
            verdict,
            if corrected {
                "user_correction"
            } else if e.check_repair && !applied {
                "recorded_checks"
            } else {
                "observed_run"
            },
            &format!("journal://{}/{}", e.session, e.seq),
        )
        .await?;
    }
    Ok(())
}

pub async fn record_feedback(flow: &Flow, key: &str, episode: &str, lesson: &str, verdict: &str, source: &str, evidence: &str) -> Result<(), RpcError> {
    put(
        flow,
        vec![json!({"label": "TerminalFeedback", "key": key, "props": {
            "verdict": verdict, "source": source, "evidence": evidence, "created_ms": now_ms()
        }})],
        vec![edge("TerminalFeedback", key, "FOR", "Knowledge", lesson), edge("TerminalFeedback", key, "FROM", "TerminalEpisode", episode)],
    )
    .await
}

#[derive(Default)]
pub struct Score {
    pub helped: u64,
    pub hurt: u64,
    pub seen: u64,
}

/// Replays of the old `recorded_context_replay` source were graded on the very episode a lesson
/// was learned from, which proves nothing; they are not counted.
pub async fn scores(flow: &Flow) -> Result<HashMap<String, Score>, RpcError> {
    let found = rows(flow, "MATCH (f:TerminalFeedback)-[:FOR]->(k:Knowledge) WHERE f.source <> 'recorded_context_replay' RETURN k.id, f.verdict, count(f)", json!({}), 5000).await?;
    let mut scores: HashMap<String, Score> = HashMap::new();
    for row in found {
        let Some(id) = row.first().and_then(Value::as_str) else { continue };
        let count = row.get(2).and_then(Value::as_u64).unwrap_or(0);
        let score = scores.entry(id.to_owned()).or_default();
        score.seen += count;
        match row.get(1).and_then(Value::as_str) {
            Some("helped") => score.helped += count,
            Some("hurt") => score.hurt += count,
            _ => {}
        }
    }
    Ok(scores)
}

/// More harmful than helpful across at least three observations.
fn harmful(score: Option<&Score>) -> bool {
    score.is_some_and(|s| s.hurt > s.helped && s.hurt + s.helped >= 3)
}

/// Each lesson carries its score where memory shows it, and a harmful one is withdrawn. The
/// counters only add, so they are brought up to the graph's count, never past it.
async fn settle_lessons(flow: &Flow) -> Result<(), RpcError> {
    let scores = scores(flow).await?;
    let lessons: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson", "include_history": true})).await?)?;
    for item in &lessons.items {
        let Some(score) = scores.get(&item.id) else { continue };
        let more = |now: u64, stored: u32| now.saturating_sub(u64::from(stored)) as u32;
        let (seen, helped, hurt) = (more(score.seen, item.seen), more(score.helped, item.helped), more(score.hurt, item.hurt));
        if seen + helped + hurt > 0 {
            flow.ctx()?.call(memory::KNOWLEDGE_COUNT, json!({"id": item.id, "seen": seen, "helped": helped, "hurt": hurt})).await?;
        }
        if harmful(Some(score)) && item.by == "chatflow-terminal" && !matches!(item.state.as_str(), "withdrawn" | "superseded") {
            flow.ctx()?
                .call(memory::KNOWLEDGE_WITHDRAW, json!({"id": item.id, "reason": "More harmful than helpful across at least three recorded observations", "by": "chatflow-terminal"}))
                .await?;
        }
    }
    Ok(())
}

pub struct Generated {
    pub result: ChatResult,
    pub model_id: String,
}

/// Borrow the existing shared model at idle. Foreground work cancels the stream; cancellation
/// unwinds through lease release, and a process disconnect releases claims held by its caller.
pub async fn background(flow: &Flow, purpose: &str, messages: Vec<ChatMessage>, schema: Option<Value>, cancel: &CancellationToken) -> Result<Generated, RpcError> {
    check_cancel(cancel)?;
    let key = format!("ct-learning-{purpose}-{}", uuid::Uuid::new_v4());
    let ctx = flow.ctx()?;
    let claimed = async {
        let mut claim = ctx.call_stream(mesh::CLAIM, json!({"kind": "model", "tags": [tags::CODING, tags::OFFICE, tags::SMALL_OFFICE], "session_id": key, "foreground": false, "wait": true}))?;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => { claim.cancel(); return Err(RpcError::cancelled()); },
                item = claim.next() => if item.is_none() { break },
            }
        }
        claim.finish().await.map(|_| ())
    }
    .await;
    let outcome = async {
        if let Err(error) = claimed {
            if cancel.is_cancelled() {
                return Err(error);
            }
            // Match foreground fallback when no mesh provider is installed. The local scheduler
            // still enforces idle_only and background priority.
            if !matches!(error.code.as_str(), codes::UNKNOWN_METHOD | codes::UNAVAILABLE | codes::NOT_FOUND) {
                return Err(error);
            }
        }
        check_cancel(cancel)?;
        let info = ctx.call("model.info", json!({"session_id": key})).await?;
        let model_id = field(&info, "model_id").to_owned();
        let params = ChatParams {
            messages,
            tools: Vec::new(),
            tool_choice: Some(json!("none")),
            grammar: None,
            json_schema: schema,
            sampling: Sampling { temperature: 0.0, ..Sampling::default() },
            thinking: Thinking::default(),
            priority: Priority::Background,
            cache_key: Some(key.clone()),
            stop: Vec::new(),
            max_tokens: Some(800),
            idle_only: true,
        };
        let mut stream = ctx.call_stream("model.chat", serde_json::to_value(params)?)?;
        loop {
            tokio::select! {
                _ = cancel.cancelled() => { stream.cancel(); return Err(RpcError::cancelled()); },
                item = stream.next() => if item.is_none() { break },
            }
        }
        let result = parse_params(stream.finish().await?)?;
        let after = ctx.call("model.info", json!({"session_id": key})).await?;
        if field(&after, "model_id") != model_id {
            return Err(RpcError::internal("model changed during terminal learning"));
        }
        Ok(Generated { result, model_id })
    }
    .await;
    let _ = ctx.call(mesh::RELEASE, json!({"kind": "model", "session_id": key})).await;
    let _ = ctx.call(mesh::PLACE_END, json!({"session_id": key})).await;
    outcome
}

/// The graph read, for other parts of the flow.
pub const GRAPH_QUERY: &str = memory::GRAPH_QUERY;

pub async fn rows(flow: &Flow, cypher: &str, params: Value, limit: u32) -> Result<Vec<Vec<Value>>, RpcError> {
    let result = flow.ctx()?.call(memory::GRAPH_QUERY, json!({"cypher": cypher, "params": params, "limit": limit})).await?;
    if result.get("truncated").and_then(Value::as_bool) == Some(true) {
        return Err(RpcError::internal("learning graph result exceeded its row limit; no partial score used"));
    }
    serde_json::from_value(result.get("rows").cloned().unwrap_or(Value::Null)).map_err(|error| RpcError::internal(format!("learning graph rows: {error}")))
}

pub async fn put(flow: &Flow, nodes: Vec<Value>, edges: Vec<Value>) -> Result<(), RpcError> {
    flow.ctx()?.call(memory::GRAPH_PUT, json!({"nodes": nodes, "edges": edges})).await.map(|_| ())
}

pub fn edge(from: &str, from_key: &str, rel: &str, to: &str, to_key: &str) -> Value {
    json!({"from": {"label": from, "key": from_key}, "rel": rel, "to": {"label": to, "key": to_key}})
}

pub fn field<'a>(value: &'a Value, name: &str) -> &'a str {
    value.get(name).and_then(Value::as_str).unwrap_or("")
}
pub fn cut(text: &str, count: usize) -> String {
    text.chars().take(count).collect()
}
pub fn check_cancel(cancel: &CancellationToken) -> Result<(), RpcError> {
    if cancel.is_cancelled() { Err(RpcError::cancelled()) } else { Ok(()) }
}
pub fn output_text(value: &Value) -> String {
    value.get("lines").and_then(Value::as_array).into_iter().flatten().filter_map(|line| line.get("text").and_then(Value::as_str)).collect::<Vec<_>>().join("\n")
}
fn parse_json<T: serde::de::DeserializeOwned>(text: &str) -> Result<T, RpcError> {
    let text = text.trim();
    let text = text.strip_prefix("```json").or_else(|| text.strip_prefix("```")).and_then(|s| s.trim().strip_suffix("```")).unwrap_or(text);
    serde_json::from_str(text.trim()).map_err(|error| RpcError::internal(format!("terminal learning JSON: {error}")))
}

/// Once per start, for records earlier versions wrote: an episode's snapshot moves from JSON text
/// to the episodes stream, and properties that copied an edge or held JSON are dropped.
async fn migrate(flow: &Flow) -> Result<(), RpcError> {
    let gone = |names: &[&str]| names.iter().map(|name| (name.to_string(), Value::Null)).collect::<serde_json::Map<_, _>>();
    loop {
        let old = rows(flow, "MATCH (e:TerminalEpisode) WHERE e.session_id IS NOT NULL OR e.messages_json IS NOT NULL RETURN e.key, e.messages_json, e.shown_json LIMIT 1000", json!({}), 1000).await?;
        if old.is_empty() {
            break;
        }
        let mut records = Vec::new();
        let mut nodes = Vec::new();
        for row in &old {
            let value = |index: usize| row.get(index).and_then(Value::as_str).and_then(|text| serde_json::from_str::<Value>(text).ok()).unwrap_or(json!([]));
            let key = row.first().and_then(Value::as_str).unwrap_or("");
            let mut props = gone(&["session_id", "run_id", "cwd", "outcome_id", "outcome_command", "messages_json", "shown_json"]);
            if row.get(1).is_some_and(|v| !v.is_null()) {
                records.push(json!({"episode": key, "messages": value(1), "shown": value(2)}));
                props.insert("at_ms".into(), json!(now_ms()));
            }
            nodes.push(json!({"label": "TerminalEpisode", "key": key, "props": props}));
        }
        if !records.is_empty() {
            append_episodes(flow, records).await?;
        }
        put(flow, nodes, Vec::new()).await?;
    }
    for (label, names) in [("TerminalFeedback", &["lesson_id"][..]), ("TerminalReplay", &["lesson_id", "lesson_text"][..]), ("TerminalLearningPass", &["distilled_json"][..])] {
        loop {
            let old = rows(flow, &format!("MATCH (n:{label}) WHERE n.{} IS NOT NULL RETURN n.key LIMIT 1000", names[0]), json!({}), 1000).await?;
            if old.is_empty() {
                break;
            }
            let nodes = old.iter().filter_map(|row| row.first()?.as_str()).map(|key| json!({"label": label, "key": key, "props": gone(names)})).collect();
            put(flow, nodes, Vec::new()).await?;
        }
    }
    Ok(())
}

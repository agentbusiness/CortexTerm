//! CT's own learning loop. Journals are evidence; checkpoints, snapshots, lessons and verdicts
//! live in CT's graph. Stable event keys make retrying a pass safe, including after a hot swap.
//! Scores are derived from feedback nodes, rather than non-idempotent counter increments.

use crate::{flow::Flow, replay, security};
use cc_protocol::contracts::frame::{JournalEntry, JournalReadResult, SessionListResult, kinds};
use cc_protocol::contracts::memory::{KnowledgeItem, KnowledgeListResult, KnowledgeSearchResult, methods as memory};
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
const MAX_BACKLOG: usize = 8;
const MAX_LESSONS: usize = 4;
const MAX_FACTS: usize = 4;

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
    pub shown: Vec<Shown>,
    pub failure: String,
}

/// Only the folder and its ancestors match a local lesson; path prefixes such as /api2 do not.
fn in_scope(item: &KnowledgeItem, cwd: &str) -> bool {
    item.aliases.iter().filter_map(|a| a.strip_prefix("folder:")).all(|folder| Path::new(cwd).starts_with(folder))
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

pub async fn recall(flow: &Flow, question: &str, cwd: &str, failed_id: Option<&str>) -> Result<Recall, RpcError> {
    let mut recalled = Recall::default();
    if let Some(id) = failed_id {
        let run = rows(flow, "MATCH (r:CommandRun {key: $id}) RETURN r.command, r.exit_code", json!({"id": id}), 1).await?;
        if let Some(row) = run.first()
            && row.get(1).and_then(Value::as_i64).is_some_and(|code| code != 0)
        {
            let output = flow.ctx()?.call("terminal.run.output", json!({"run_id": id, "from": -60, "count": 60})).await?;
            recalled.failure = failure_key(row.first().and_then(Value::as_str).unwrap_or(""), &output_text(&output));
        }
    }
    let facts: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "fact"})).await?)?;
    for item in facts
        .items
        .iter()
        .filter(|item| {
            item.name.strip_prefix("place ").and_then(|name| name.split_once(": ")).is_some_and(|(folder, _)| Path::new(cwd).starts_with(folder))
                && in_scope(item, cwd)
                && security::guarded_reasons(&item.text).is_none()
        })
        .take(MAX_FACTS)
    {
        recalled.shown.push(shown(item, ""));
    }
    let mut candidates: HashMap<String, KnowledgeItem> = HashMap::new();
    let searched = flow.ctx()?.call(memory::KNOWLEDGE_SEARCH, json!({"text": cut(question, 1000), "kind": "lesson", "limit": 16})).await;
    match searched.and_then(parse_params::<KnowledgeSearchResult>) {
        Ok(searched) => {
            for item in searched.items.into_iter().filter(|item| item.score.unwrap_or(0.0) >= 0.35 && in_scope(item, cwd) && security::guarded_reasons(&item.text).is_none()) {
                candidates.insert(item.id.clone(), item);
            }
        }
        Err(error) => tracing::debug!(%error, "meaning search unavailable; folder facts and failure-key recall remain available"),
    }
    if !recalled.failure.is_empty() {
        let keyed: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson"})).await?)?;
        for mut item in keyed.items.into_iter().filter(|item| item.aliases.contains(&recalled.failure) && in_scope(item, cwd) && security::guarded_reasons(&item.text).is_none()) {
            item.score = Some(2.0);
            candidates.insert(item.id.clone(), item);
        }
    }
    let scores = match scores(flow).await {
        Ok(scores) => scores,
        Err(error) => {
            tracing::debug!(%error, "lesson scores unavailable; using folder facts only");
            return Ok(recalled);
        }
    };
    let mut candidates: Vec<_> = candidates.into_values().collect();
    candidates.retain(|item| !scores.get(&item.id).is_some_and(|score| score.hurt > score.helped && score.hurt + score.helped >= 3));
    candidates.sort_by(|a, b| {
        let rank = |item: &KnowledgeItem| item.score.unwrap_or(0.0) + scores.get(&item.id).map_or(0.0, |s| 0.05 * (s.helped.min(5) as f64 - s.hurt.min(5) as f64));
        rank(b).total_cmp(&rank(a)).then_with(|| a.id.cmp(&b.id))
    });
    for item in candidates.into_iter().take(MAX_LESSONS) {
        let key = if item.aliases.contains(&recalled.failure) { &recalled.failure } else { "" };
        recalled.shown.push(shown(&item, key));
    }
    Ok(recalled)
}

/// Failure-key recall happens immediately after a failed check, once per item per turn.
pub async fn at_failure(flow: &Flow, key: &str, cwd: &str, already: &[Shown]) -> Result<Vec<Shown>, RpcError> {
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
                && !scores.get(&item.id).is_some_and(|s| s.hurt > s.helped && s.hurt + s.helped >= 3)
        })
        .take(2)
        .map(|item| shown(item, key))
        .collect())
}

fn shown(item: &KnowledgeItem, failure: &str) -> Shown {
    Shown { id: item.id.clone(), name: item.name.clone(), text: cut(&item.text, 600), kind: item.kind.clone(), failure: failure.into(), index: 0 }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Episode {
    pub session: String,
    pub run: String,
    pub seq: u64,
    pub ts_ms: u64,
    pub question: String,
    pub intent: String,
    pub cwd: String,
    pub term_id: String,
    pub failure: String,
    pub answer: String,
    pub proposal: String,
    pub proposal_ms: u64,
    pub facts: String,
    pub status: String,
    pub messages: Vec<ChatMessage>,
    pub shown: Vec<Shown>,
    pub checks: String,
    pub outcome_id: String,
    pub outcome_command: String,
    pub outcome_exit: Option<i64>,
    pub outcome_failure: String,
    pub check_repair: bool,
    pub correction: String,
    pub correction_seq: u64,
}

impl Episode {
    pub fn key(&self) -> String {
        format!("{}/{}", self.session, self.run)
    }
    fn revision(&self) -> String {
        format!("{}/{}/{}/{}", self.key(), self.outcome_id, self.outcome_exit.map_or("pending".into(), |c| c.to_string()), self.correction_seq)
    }
    pub fn verified_fix(&self) -> bool {
        let program = command_family(&self.outcome_command);
        self.outcome_exit == Some(0) && !program.is_empty() && self.failure.starts_with(&format!("failed {program} "))
    }
}

/// Serial passes are bounded so a large history cannot monopolize the shared model.
async fn cycle(flow: &Flow, cancel: &CancellationToken) -> Result<(), RpcError> {
    let listed: SessionListResult = parse_params(flow.ctx()?.call("frame.session.list", json!({})).await?)?;
    let mut sessions: Vec<_> = listed.sessions.into_iter().filter(|s| s.flow == "terminal").collect();
    sessions.sort_by(|a, b| b.updated_ms.cmp(&a.updated_ms));
    let mut taken = 0;
    for session in sessions {
        check_cancel(cancel)?;
        let read: JournalReadResult = parse_params(flow.ctx()?.call("frame.journal.read", json!({"session_id": session.id})).await?)?;
        let mut seen = HashSet::new();
        for entry in read.entries.iter().rev().filter(|e| e.kind == kinds::STATUS && matches!(field(&e.data, "state"), "done" | "failed" | "cancelled")) {
            let run = field(&entry.data, "run_id");
            if run.is_empty() || !seen.insert(run.to_owned()) {
                continue;
            }
            let Some(mut episode) = episode(&session.id, run, &read.entries) else { continue };
            resolve_outcome(flow, &mut episode, &read.entries).await?;
            let key = episode.key();
            let revision = episode.revision();
            let done = rows(flow, "MATCH (p:TerminalLearningPass {key: $key}) RETURN p.state", json!({"key": revision}), 1).await?;
            if done.first().and_then(|r| r.first()).and_then(Value::as_str) == Some("done") {
                continue;
            }
            check_cancel(cancel)?;
            persist_episode(flow, &episode).await?;
            learn_episode(flow, &episode, cancel).await?;
            taken += 1;
            tracing::debug!(episode = %key, "terminal learning pass kept");
            if taken >= MAX_BACKLOG {
                withdraw_harmful(flow).await?;
                flow.wake_learning();
                return Ok(());
            }
        }
    }
    check_cancel(cancel)?;
    withdraw_harmful(flow).await?;
    replay::one(flow, cancel).await?;
    check_cancel(cancel)?;
    night_report(flow).await
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
        intent: field(&user.data, "intent").into(),
        cwd: value("cwd").as_str().unwrap_or("").into(),
        term_id: field(&user.data, "term_id").into(),
        failure: value("failure").as_str().unwrap_or("").into(),
        answer: cut(mine.iter().rev().find(|e| e.kind == kinds::ASSISTANT_MESSAGE).map(|e| field(&e.data, "text")).unwrap_or(""), 4000),
        proposal: proposal.into(),
        status: status.into(),
        proposal_ms: mine.iter().rev().find(|e| e.kind == "command_proposal").map_or(0, |e| e.ts_ms),
        facts: value("facts").as_str().unwrap_or("").to_owned(),
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
    if !episode.outcome_id.is_empty() {
        let found = rows(flow, "MATCH (r:CommandRun {key: $id}) RETURN r.command, r.exit_code", json!({"id": episode.outcome_id}), 1).await?;
        if let Some(row) = found.first() {
            episode.outcome_command = row.first().and_then(Value::as_str).unwrap_or("").into();
            episode.outcome_exit = row.get(1).and_then(Value::as_i64).or(episode.outcome_exit);
        }
    }
    if episode.outcome_exit.is_some_and(|code| code != 0) && !episode.outcome_id.is_empty() {
        let output = flow.ctx()?.call("terminal.run.output", json!({"run_id": episode.outcome_id, "from": -60, "count": 60})).await?;
        episode.outcome_failure = failure_key(&episode.outcome_command, &output_text(&output));
    }
    Ok(())
}

pub async fn persist_episode(flow: &Flow, e: &Episode) -> Result<(), RpcError> {
    let key = e.key();
    let mut nodes = vec![json!({"label": "TerminalEpisode", "key": key, "props": {
        "session_id": e.session, "run_id": e.run, "source_seq": e.seq, "created_ms": e.ts_ms,
        "question": e.question, "intent": e.intent, "cwd": e.cwd, "failure": e.failure,
        "answer": e.answer, "proposal": e.proposal, "proposal_ms": e.proposal_ms, "facts": e.facts, "status": e.status,
        "messages_json": serde_json::to_string(&e.messages)?, "shown_json": serde_json::to_string(&e.shown)?,
        "checks": e.checks, "outcome_id": e.outcome_id, "outcome_command": e.outcome_command,
        "outcome_exit": e.outcome_exit, "outcome_failure": e.outcome_failure, "verified_fix": e.verified_fix(), "check_repair": e.check_repair, "correction": e.correction, "correction_seq": e.correction_seq
    }})];
    let mut edges = vec![edge("TerminalEpisode", &key, "OF", "Session", &e.session)];
    if !e.cwd.is_empty() {
        nodes.push(json!({"label": "Folder", "key": e.cwd}));
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

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Distilled {
    useful: String,
    lesson: String,
    anchor: String,
    scope: String,
    correction_quote: String,
    contradicted: Vec<String>,
}

async fn learn_episode(flow: &Flow, e: &Episode, cancel: &CancellationToken) -> Result<(), RpcError> {
    let pass_key = e.revision();
    let prior = rows(flow, "MATCH (p:TerminalLearningPass {key: $key}) RETURN p.distilled_json", json!({"key": pass_key}), 1).await?;
    let stored = prior.first().and_then(|r| r.first()).and_then(Value::as_str).filter(|s| !s.is_empty());
    let lesson: Option<Distilled> = if let Some(stored) = stored {
        serde_json::from_str(stored).map_err(|error| RpcError::internal(format!("learning checkpoint: {error}")))?
    } else if e.status != "cancelled" && (!e.failure.is_empty() || e.outcome_exit.is_some_and(|code| code != 0) || !e.correction.is_empty() || e.checks.contains("Not run:")) {
        let schema: Value = serde_json::from_str(&std::fs::read_to_string(flow.data_file("schemas/learn.json")).map_err(|error| RpcError::internal(error.to_string()))?)?;
        let card = json!({"question": e.question, "intent": e.intent, "folder": e.cwd, "failure": e.failure, "facts": e.facts, "checks": e.checks,
            "answer": e.answer, "proposal": e.proposal, "observed_command": e.outcome_command, "observed_exit": e.outcome_exit, "verified_fix": e.verified_fix(), "check_repair": e.check_repair,
            "next_user_message": e.correction, "shown": e.shown});
        let result =
            background(flow, "learn", vec![ChatMessage::new("system", flow.prompt("learn")?), ChatMessage::new("user", security::guard(&card.to_string()))], Some(schema), cancel)
                .await?;
        if result.result.finish_reason != "stop" {
            return Err(RpcError::internal("terminal lesson extraction did not finish"));
        }
        let learned: Distilled = parse_json(&result.result.content)?;
        Some(learned)
    } else {
        None
    };
    check_cancel(cancel)?;
    // Persist the actual extraction before any side effect, so a retry does not ask for a new lesson.
    pass(flow, e, &pass_key, "distilled", serde_json::to_string(&lesson)?).await?;
    let mut lesson_id = None;
    if let Some(learned) = &lesson {
        let text = learned.lesson.split_whitespace().collect::<Vec<_>>().join(" ");
        let anchor_ok = matches!(learned.anchor.as_str(), "tool:run" | "tool:skill" | "approach") || learned.anchor.starts_with("command:");
        // A model may propose a lesson, never relax the command risk policy through memory.
        let explicit_correction = !learned.correction_quote.trim().is_empty() && e.correction.contains(&learned.correction_quote);
        let demonstrated = e.verified_fix() || e.check_repair || explicit_correction;
        if demonstrated && learned.useful == "yes" && !text.is_empty() && text.chars().count() <= 240 && anchor_ok && security::guarded_reasons(&text).is_none() {
            lesson_id = keep(flow, e, learned, &text).await?;
        }
    }
    feedback(flow, e, lesson.as_ref()).await?;
    check_cancel(cancel)?;
    pass(flow, e, &pass_key, "done", serde_json::to_string(&lesson)?).await?;
    flow.journal(
        &e.session,
        kinds::NOTE,
        json!({"purpose": "terminal_learned", "run_id": e.run,
        "pass": pass_key, "lesson_id": lesson_id, "host_message": false, "text": ""}),
    )
    .await?;
    Ok(())
}

async fn pass(flow: &Flow, e: &Episode, key: &str, state: &str, distilled: String) -> Result<(), RpcError> {
    put(
        flow,
        vec![json!({"label": "TerminalLearningPass", "key": key, "props": {"state": state, "distilled_json": distilled, "updated_ms": now_ms()}})],
        vec![edge("TerminalLearningPass", key, "FROM", "TerminalEpisode", &e.key())],
    )
    .await
}

async fn keep(flow: &Flow, e: &Episode, learned: &Distilled, text: &str) -> Result<Option<String>, RpcError> {
    let local = learned.scope != "general" || text.contains('/') || text.contains('~') || (!e.cwd.is_empty() && text.contains(&e.cwd));
    if local && e.cwd.is_empty() {
        return Ok(None);
    }
    let scope = if local { format!("folder:{}", e.cwd) } else { format!("os:{}", std::env::consts::OS) };
    let name = format!("{} [{}]: {}", learned.anchor, scope, text);
    let all: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson", "include_history": true})).await?)?;
    let mut existing = all.items.iter().find(|item| item.name == name).cloned();
    if existing.is_none() {
        let similar: KnowledgeSearchResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_SEARCH, json!({"kind": "lesson", "text": text, "limit": 3})).await?)?;
        existing =
            similar.items.into_iter().find(|item| item.score.unwrap_or(0.0) >= 0.90 && item.name.starts_with(&format!("{} [", learned.anchor)) && item.aliases.contains(&scope));
    }
    // A user editing a learned item owns it; the learner does not replace that provenance.
    if existing.as_ref().is_some_and(|item| item.by != "chatflow-terminal") {
        return Ok(None);
    }
    if existing.as_ref().is_some_and(|item| matches!(item.state.as_str(), "withdrawn" | "superseded")) {
        return Ok(None);
    }
    let name = existing.as_ref().map(|item| item.name.as_str()).unwrap_or(&name);
    let mut aliases = vec![scope];
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
    let mut edges = vec![edge("Knowledge", &item.id, "LEARNED_FROM", "TerminalEpisode", &e.key())];
    let mut nodes = Vec::new();
    if local {
        nodes.push(json!({"label": "Folder", "key": e.cwd}));
        edges.push(edge("Knowledge", &item.id, "ABOUT", "Folder", &e.cwd));
    }
    put(flow, nodes, edges).await?;
    Ok(Some(item.id))
}

async fn feedback(flow: &Flow, e: &Episode, distilled: Option<&Distilled>) -> Result<(), RpcError> {
    let lessons: Vec<_> = e.shown.iter().filter(|s| s.kind == "lesson").collect();
    let matching = lessons.iter().filter(|s| !s.failure.is_empty() && s.failure == e.failure).count();
    for item in lessons {
        let corrected = distilled.is_some_and(|d| !d.correction_quote.trim().is_empty() && e.correction.contains(&d.correction_quote) && d.contradicted.contains(&item.id));
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
            "lesson_id": lesson, "verdict": verdict, "source": source, "evidence": evidence, "created_ms": now_ms()
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

pub async fn scores(flow: &Flow) -> Result<HashMap<String, Score>, RpcError> {
    let found = rows(flow, "MATCH (f:TerminalFeedback) RETURN f.lesson_id, f.verdict, count(f)", json!({}), 5000).await?;
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

async fn withdraw_harmful(flow: &Flow) -> Result<(), RpcError> {
    for (id, score) in scores(flow).await? {
        if score.hurt > score.helped && score.hurt + score.helped >= 3 {
            let item: KnowledgeItem = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_GET, json!({"id": id})).await?)?;
            if item.kind == "lesson" && item.by == "chatflow-terminal" && item.state != "withdrawn" {
                flow.ctx()?
                    .call(
                        memory::KNOWLEDGE_WITHDRAW,
                        json!({"id": id, "reason": "More harmful than helpful across at least three recorded observations", "by": "chatflow-terminal"}),
                    )
                    .await?;
            }
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
        let mut claim = ctx.call_stream(mesh::CLAIM, json!({"kind": "model", "tags": [tags::CODING, tags::OFFICE], "session_id": key, "foreground": false, "wait": true}))?;
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

async fn night_report(flow: &Flow) -> Result<(), RpcError> {
    // Day keys are UTC, matching the journal timestamps and CC's daily review convention.
    let day = now_ms() / 86_400_000;
    let key = format!("terminal-{day}");
    if !rows(flow, "MATCH (r:TerminalNightReport {key: $key}) RETURN r.key", json!({"key": key}), 1).await?.is_empty() {
        return Ok(());
    }
    let lessons: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson"})).await?)?;
    let scores = scores(flow).await?;
    let replays = rows(flow, "MATCH (r:TerminalReplay) WHERE r.created_ms >= $since RETURN r.lesson_id, r.verdict, r.oracle", json!({"since": day * 86_400_000}), 5000).await?;
    let mut text = vec!["# CortexTerm learning review".to_owned(), "Proposals only: skills and risk-engine code are never changed by learning.".into()];
    for item in lessons.items.iter().filter(|item| item.by == "chatflow-terminal") {
        let score = scores.get(&item.id);
        let (helped, hurt, seen) = score.map_or((0, 0, 0), |s| (s.helped, s.hurt, s.seen));
        text.push(format!("- {}: helped {helped}, hurt {hurt}, observations {seen}; {}", item.name, item.evidence.join(", ")));
        if helped >= 3 && hurt == 0 {
            text.push(format!("  Proposed skill addition: {}", item.text));
        }
        if helped >= 5 && hurt == 0 && item.aliases.iter().any(|a| a.starts_with("failed ") || a.starts_with("refused ")) {
            text.push(format!("  Proposed host repair review: {}", item.text));
        }
    }
    for row in &replays {
        text.push(format!("- Recorded-context replay: {}", serde_json::to_string(row)?));
    }
    let machine = flow.ctx()?.call(memory::GRAPH_MACHINE, json!({})).await?;
    put(
        flow,
        vec![json!({"label": "TerminalNightReport", "key": key, "props": {"text": text.join("\n"), "created_ms": now_ms(), "replays": replays.len()}})],
        vec![edge("TerminalNightReport", &key, "ON", "Machine", field(&machine, "key"))],
    )
    .await
}

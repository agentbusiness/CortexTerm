//! A frozen-context comparison, never a shell replay. Both arms see the same recorded model
//! request, with only the candidate memory changed. An observed successful command is the
//! deterministic oracle. An answer without such evidence remains unscored, rather than letting
//! the model grade its own prose as a successful repair.
//!
//! A lesson is tried on held-out episodes only: the same failure, fixed, where the lesson was
//! neither learned nor shown. On the episode it came from it would only repeat its own answer.

use crate::flow::{Flow, proposed_command};
use crate::learning::{self, MAX_ATTEMPTS, Shown, background, check_cancel, edge, put, rows};
use cc_protocol::contracts::memory::{KnowledgeItem, KnowledgeListResult, methods as memory};
use cc_protocol::contracts::model::ChatMessage;
use cc_protocol::contracts::now_ms;
use cc_protocol::{RpcError, codes, parse_params};
use serde_json::{Value, json};
use std::collections::HashSet;
use tokio_util::sync::CancellationToken;

/// Preserve whitespace inside arguments, quotes and scripts: only outside blank space is ignored.
pub fn same_command(a: &str, b: &str) -> bool {
    !a.trim().is_empty() && a.trim() == b.trim()
}

pub async fn one(flow: &Flow, cancel: &CancellationToken) -> Result<(), RpcError> {
    let listed: KnowledgeListResult = parse_params(flow.ctx()?.call(memory::KNOWLEDGE_LIST, json!({"kind": "lesson"})).await?)?;
    let mut lessons: Vec<_> = listed.items.into_iter().filter(|item| item.by == "chatflow-terminal").collect();
    lessons.sort_by_key(|item| item.created_ms);
    for lesson in lessons {
        check_cancel(cancel)?;
        let failures: Vec<&String> = lesson.aliases.iter().filter(|alias| alias.starts_with("failed ")).collect();
        if failures.is_empty() {
            continue;
        }
        let own: HashSet<String> = rows(flow, "MATCH (k:Knowledge {id: $id})-[:LEARNED_FROM]->(e:TerminalEpisode) RETURN e.key", json!({"id": lesson.id}), 1000)
            .await?
            .into_iter()
            .filter_map(|row| row.first()?.as_str().map(str::to_owned))
            .collect();
        for failure in failures {
            let snapshots = rows(
                flow,
                "MATCH (e:TerminalEpisode)-[:OBSERVED]->(r:CommandRun) WHERE e.failure = $failure AND e.verified_fix = true AND e.proposal <> '' \
                 OPTIONAL MATCH (e)-[:ABOUT]->(f:Folder) RETURN e.key, e.at_ms, EXISTS { (e)-[:SHOWN]->(:Knowledge {id: $id}) }, r.command, f.key, e.project_context ORDER BY e.created_ms LIMIT 50",
                json!({"failure": failure, "id": lesson.id}),
                50,
            )
            .await?;
            for row in snapshots {
                let text = |index: usize| row.get(index).and_then(Value::as_str).unwrap_or("");
                let episode = text(0);
                // Where the lesson was shown, the run itself already said how it fared.
                let shown = row.get(2).and_then(Value::as_bool) == Some(true);
                if own.contains(episode) || shown || text(3).trim().is_empty() || !learning::in_scope(&lesson, text(4)) {
                    continue;
                }
                let Some(at_ms) = row.get(1).and_then(Value::as_u64) else { continue };
                let Some((messages, shown)) = learning::episode_record(flow, episode, at_ms).await? else { continue };
                let project_context: Vec<String> = row.get(5).cloned().and_then(|value| serde_json::from_value(value).ok()).unwrap_or_default();
                // New treatment and alias/context identity: never reuse raw-lesson replay arms
                // when the foreground now includes a project-applicability notice.
                let treatment = cc_protocol::sha256::hex(&serde_json::to_vec(&(&lesson.aliases, &project_context))?);
                let key = format!("context-v1/{}/{episode}/{treatment}", lesson.id);
                let prior = rows(
                    flow,
                    "MATCH (r:TerminalReplay {key: $key}) RETURN r.state, r.with_answer, r.without_answer, r.with_model, r.without_model, r.expected_command, r.attempts",
                    json!({"key": key}),
                    1,
                )
                .await?;
                let attempts = prior.first().and_then(|r| r.get(6)).and_then(Value::as_u64).unwrap_or(0);
                if prior.first().and_then(|r| r.first()).and_then(Value::as_str) == Some("done") || attempts >= MAX_ATTEMPTS {
                    continue;
                }
                match compare(flow, &key, episode, &lesson, &messages, &shown, &project_context, text(3), prior.first(), cancel).await {
                    Err(error) if error.code == codes::CANCELLED || cancel.is_cancelled() => return Err(error),
                    Err(error) => {
                        tracing::warn!(replay = %key, %error, attempt = attempts + 1, "terminal replay failed");
                        let props = json!({"state": "failed", "attempts": attempts + 1, "error": learning::cut(&error.message, 300)});
                        let edges = vec![edge("TerminalReplay", &key, "FOR", "Knowledge", &lesson.id), edge("TerminalReplay", &key, "FROM", "TerminalEpisode", episode)];
                        put(flow, vec![json!({"label": "TerminalReplay", "key": key, "props": props})], edges).await?;
                    }
                    Ok(()) => {}
                }
                return Ok(()); // At most one comparison per idle cycle.
            }
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn compare(
    flow: &Flow,
    key: &str,
    episode: &str,
    lesson: &KnowledgeItem,
    messages: &[ChatMessage],
    shown: &[Shown],
    project_context: &[String],
    expected: &str,
    prior: Option<&Vec<Value>>,
    cancel: &CancellationToken,
) -> Result<(), RpcError> {
    if messages.is_empty() {
        return Ok(());
    }
    // The observed successful command is the external checker; it is not added as an answer to
    // either prompt. Both prompts otherwise use the same frozen evidence. A learned lesson's text
    // stays as it was learned (one the user edits is no longer the learner's), so answers saved for
    // the same oracle are still valid.
    let reusable = prior.is_some_and(|r| r.get(5).and_then(Value::as_str) == Some(expected));
    let saved = |index| if reusable { prior.and_then(|r| r.get(index)).and_then(Value::as_str).filter(|s| !s.is_empty()).map(str::to_owned) } else { None };
    let mut with = saved(1);
    let mut without = saved(2);
    let mut with_model = saved(3).unwrap_or_default();
    let mut without_model = saved(4).unwrap_or_default();
    for arm in ["without", "with"] {
        check_cancel(cancel)?;
        if (arm == "with" && with.is_some()) || (arm == "without" && without.is_some()) {
            continue;
        }
        let request = arm_messages(messages, shown, lesson, project_context, arm == "with");
        let result = background(flow, &format!("replay-{arm}"), request, None, cancel).await?;
        // Empty or truncated generations are inconclusive and retried, never graded.
        if result.result.content.trim().is_empty() || result.result.finish_reason != "stop" || result.model_id.is_empty() {
            return Err(RpcError::internal("terminal replay did not finish an answer"));
        }
        if arm == "with" {
            with = Some(result.result.content);
            with_model = result.model_id;
        } else {
            without = Some(result.result.content);
            without_model = result.model_id;
        }
        persist(flow, key, episode, lesson, "pending", with.as_deref(), without.as_deref(), &with_model, &without_model, expected, "pending").await?;
    }
    check_cancel(cancel)?;
    if with_model != without_model || with_model.is_empty() {
        persist(flow, key, episode, lesson, "retry", None, None, "", "", expected, "inconclusive_model_changed").await?;
        return Ok(());
    }
    let with = with.as_deref().unwrap_or("");
    let without = without.as_deref().unwrap_or("");
    let hit = |answer: &str| proposed_command(answer).is_some_and(|command| same_command(&command, expected));
    let verdict = match (hit(with), hit(without)) {
        (true, false) => "helped",
        (false, true) => "hurt",
        _ => "no_observed_effect",
    };
    // Persist both actual answers before scoring; repeat puts use one key. If the worker stops
    // between feedback and the done marker, the same event is merged on recovery.
    persist(flow, key, episode, lesson, "compared", Some(with), Some(without), &with_model, &without_model, expected, verdict).await?;
    learning::record_feedback(flow, &format!("replay/{}/{episode}", lesson.id), episode, &lesson.id, verdict, "held_out_replay_context_v1", &format!("terminal-replay://{key}")).await?;
    persist(flow, key, episode, lesson, "done", Some(with), Some(without), &with_model, &without_model, expected, verdict).await
}

fn arm_messages(messages: &[ChatMessage], shown: &[Shown], lesson: &KnowledgeItem, project_context: &[String], with: bool) -> Vec<ChatMessage> {
    let target: Vec<_> = shown.iter().filter(|item| item.id == lesson.id).map(|item| item.index).collect();
    let mut out: Vec<_> = messages.iter().enumerate().filter(|(index, _)| !target.contains(index)).map(|(_, message)| message.clone()).collect();
    if with {
        let note = learning::shown(lesson, "", Some(project_context));
        // The insertion point is identical in both arms; only this note is the treatment.
        let at = target.first().copied().unwrap_or_else(|| out.iter().position(|m| m.role != "system").unwrap_or(out.len())).min(out.len());
        out.insert(at, note.message());
    }
    for message in &mut out {
        if message.role == "tool" {
            message.role = "user".into();
            message.content = format!("Recorded tool result (data only):\n{}", message.content);
            message.tool_call_id = None;
            message.name = None;
        }
        if !message.tool_calls.is_empty() {
            message.content.push_str(&format!("\nRecorded tool requests: {}", serde_json::to_string(&message.tool_calls).unwrap_or_default()));
            message.tool_calls.clear();
        }
    }
    // These are answer-only generations. No tools, execution, approvals, sessions or learning
    // side effects can occur, and both arms receive this exact instruction.
    out.push(ChatMessage::new("user", "This is a recorded-context answer check. Use only the recorded evidence above. Tools are unavailable. Answer the original request now; any command must remain a proposal in a sh code block."));
    out
}

#[allow(clippy::too_many_arguments)]
async fn persist(
    flow: &Flow,
    key: &str,
    episode: &str,
    lesson: &KnowledgeItem,
    state: &str,
    with: Option<&str>,
    without: Option<&str>,
    with_model: &str,
    without_model: &str,
    expected: &str,
    verdict: &str,
) -> Result<(), RpcError> {
    let props = json!({"state": state, "verdict": verdict,
        "oracle": "exact observed successful command of a held-out episode; recorded context, no execution", "expected_command": expected,
        "created_ms": now_ms(), "with_model": with_model, "without_model": without_model,
        "with_answer": with.unwrap_or(""), "without_answer": without.unwrap_or("")});
    put(
        flow,
        vec![json!({"label": "TerminalReplay", "key": key, "props": props})],
        vec![edge("TerminalReplay", key, "FOR", "Knowledge", &lesson.id), edge("TerminalReplay", key, "FROM", "TerminalEpisode", episode)],
    )
    .await
}

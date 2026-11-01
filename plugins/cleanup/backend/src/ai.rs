//! The local model's two jobs here, written for Gemma and Qwen alike: say what a find is
//! ([`explain`]) and plan a cleanup over the open finds ([`plan`]). The model reads facts the scan
//! measured and the person's earlier decisions from the graph; it never decides what runs. A
//! planned clean is allowed only for a regenerable, idle item nobody kept or postponed; every
//! other choice is shown to the person as a suggestion.

use cc_protocol::Ctx;
use cc_protocol::contracts::cleanup::{Item, Plan, PlannedStep};
use cc_protocol::contracts::model::{ChatDelta, ChatMessage, ChatParams, ChatResult, Priority, Sampling, Thinking};
use serde_json::{Value, json};
use std::path::Path;
use std::time::Duration;

/// Items per model call: a short list a small model answers whole.
const PER_CALL: usize = 30;

pub fn short(path: &str, home: &Path) -> String {
    let home = home.to_string_lossy();
    match path.strip_prefix(home.as_ref()) {
        Some(rest) => format!("~{rest}"),
        None => path.to_owned(),
    }
}

pub fn size(bytes: u64) -> String {
    let units = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < units.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if value < 10.0 && unit > 0 { format!("{value:.1} {}", units[unit]) } else { format!("{value:.0} {}", units[unit]) }
}

fn days(ms: u64) -> String {
    if ms == 0 {
        return "unknown".into();
    }
    let days = cc_protocol::contracts::now_ms().saturating_sub(ms) / 86_400_000;
    format!("{days} days ago")
}

async fn chat(ctx: &Ctx, system: &str, user: String, schema: Option<Value>, tokens: u32) -> Result<String, String> {
    let params = ChatParams {
        messages: vec![ChatMessage::new("system", system.to_owned()), ChatMessage::new("user", user)],
        tools: Vec::new(),
        tool_choice: None,
        grammar: None,
        json_schema: schema,
        sampling: Sampling { temperature: 0.1, ..Default::default() },
        thinking: Thinking { enabled: false, effort: None, budget_tokens: None },
        priority: Priority::Foreground,
        cache_key: Some("cortexterm-cleanup".into()),
        stop: Vec::new(),
        max_tokens: Some(tokens),
        idle_only: false,
    };
    let value = serde_json::to_value(params).map_err(|e| e.to_string())?;
    let mut stream = ctx.call_stream("model.chat", value).map_err(|_| "The local model is not available.".to_owned())?;
    let work = async {
        while let Some(item) = stream.next().await {
            if serde_json::from_value::<ChatDelta>(item).is_ok_and(|d| d.kind == "tool_call") {
                return Err("The model answered with a tool call.".to_owned());
            }
        }
        let result: ChatResult = serde_json::from_value(stream.finish().await.map_err(|e| e.message)?).map_err(|e| e.to_string())?;
        Ok(result.content)
    };
    tokio::time::timeout(Duration::from_secs(180), work).await.map_err(|_| "The model did not answer within three minutes.".to_owned())?
}

const EXPLAIN: &str = "You explain disk space on a developer's computer. You get one folder or file and facts measured about it. \
In at most four short sentences say: what it most likely is and which program made it; whether removing it loses anything the person made; \
how it comes back if it is needed again. Use plain words, no lists, no headings. If the facts do not tell, say you are not sure.";

pub async fn explain(ctx: &Ctx, item: &Item, home: &Path) -> Result<String, String> {
    let path = Path::new(&item.path);
    let mut entries: Vec<String> = std::fs::read_dir(path)
        .map(|list| {
            list.flatten()
                .take(400)
                .map(|e| format!("{}{}", e.file_name().to_string_lossy(), if e.file_type().is_ok_and(|t| t.is_dir()) { "/" } else { "" }))
                .collect()
        })
        .unwrap_or_default();
    entries.sort();
    entries.truncate(25);
    let facts = format!(
        "Path: {}\nRecognised as: {} ({})\nWhat the scan knows: {}\nSize on disk: {} in {} files\nLast change inside: {}\nProject: {}\nIn use: {}\nComes back with: {}\nCleaning would: {}\nEntries inside: {}",
        short(&item.path, home),
        item.title,
        item.kind,
        item.why,
        size(item.bytes),
        item.files,
        days(item.newest_ms),
        if item.project.is_empty() { "none".into() } else { short(&item.project, home) },
        if item.in_use_by.is_empty() { "no".into() } else { item.in_use_by.join(", ") },
        if item.regenerate.is_empty() { "nothing (it does not come back)" } else { &item.regenerate },
        match item.how.as_str() {
            "trash" => "move it to the Trash",
            "clone" => "turn the copies into clones of one file (nothing is lost)",
            "command" => "run the tool's own clean command",
            "empty" => "empty the Trash for good",
            _ => "delete it",
        },
        if entries.is_empty() { "(a file)".into() } else { entries.join(", ") },
    );
    let text = chat(ctx, EXPLAIN, facts, None, 220).await?;
    Ok(text.trim().to_owned())
}

const PLAN: &str = "You plan a disk cleanup for a developer. Each numbered line is one thing on the disk, with facts the scan measured. \
For every number choose one action:\n\
clean = free it now. Good for build output of projects not worked on lately, caches, old temporary files, agent scratch, duplicate copies.\n\
later = not now, ask again in 30 days. Good for things the person may still need soon: recent work, models, transcripts, unknown folders.\n\
keep = the person wants it and it should not be offered again. Only when their earlier decisions show they keep this kind of thing.\n\
Things marked in use or review are never cleaned by you; choose later or keep for them. \
Give each a reason of one short sentence the person will read. Answer for every number.";

fn line(n: usize, item: &Item, home: &Path) -> String {
    format!(
        "{n}. {} | {} | {} | {} | {} | {} | {} | last change {}{}",
        size(item.bytes),
        item.kind,
        item.title,
        short(&item.path, home),
        if item.scope == "stale" { "older builds only" } else { "whole" },
        item.safety,
        match item.state.as_str() {
            "in_use" => "in use",
            "warm" => "changed in the last two days",
            _ => "idle",
        },
        days(item.newest_ms),
        if item.project.is_empty() { String::new() } else { format!(" | project {}", short(&item.project, home)) },
    )
}

/// The AI may clean this item without the person (the plugin's rule, not the model's).
pub fn may_clean(item: &Item) -> bool {
    item.safety == "regenerable" && item.state == "open"
}

pub async fn plan(ctx: &Ctx, items: Vec<Item>, history: Vec<String>, home: &Path) -> Result<Plan, String> {
    let schema = json!({
        "type": "object",
        "properties": { "steps": { "type": "array", "items": { "type": "object",
            "properties": { "n": { "type": "integer" }, "action": { "type": "string", "enum": ["clean", "later", "keep"] }, "reason": { "type": "string", "maxLength": 140 } },
            "required": ["n", "action", "reason"] } } },
        "required": ["steps"]
    });
    let earlier = if history.is_empty() { "none yet".to_owned() } else { history.join("\n") };
    let mut plan = Plan::default();
    for chunk in items.chunks(PER_CALL) {
        let lines: Vec<String> = chunk.iter().enumerate().map(|(i, item)| line(i + 1, item, home)).collect();
        let text = format!("The person's earlier decisions:\n{earlier}\n\nThings on the disk:\n{}", lines.join("\n"));
        let answer = chat(ctx, PLAN, text, Some(schema.clone()), 90 * chunk.len() as u32 + 200).await?;
        let value: Value = serde_json::from_str(answer.trim()).map_err(|_| "The model's plan was not valid JSON.".to_owned())?;
        for step in value.get("steps").and_then(Value::as_array).into_iter().flatten() {
            let Some(n) = step.get("n").and_then(Value::as_u64).map(|n| n as usize) else { continue };
            let Some(item) = n.checked_sub(1).and_then(|i| chunk.get(i)) else { continue };
            if plan.steps.iter().any(|s| s.id == item.id) {
                continue;
            }
            let action = step.get("action").and_then(Value::as_str).unwrap_or("later").to_owned();
            let reason: String = step.get("reason").and_then(Value::as_str).unwrap_or_default().chars().take(200).collect();
            let allowed = action != "clean" || may_clean(item);
            if action == "clean" && allowed {
                plan.freed += item.bytes;
            }
            plan.steps.push(PlannedStep { id: item.id.clone(), action, reason, allowed, bytes: item.bytes });
        }
    }
    Ok(plan)
}

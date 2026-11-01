//! The `recall` tool: what this machine's memory (its graph, `docs/GRAPH-MODEL.md`) knows, read
//! by the model when it needs it instead of finding it out again with `run`: past commands here
//! or anywhere (and what ran right after a failed one), what is installed, the project this
//! folder is in, the folders worked in, and the machines reached with ssh.
//!
//! Every answer is short, newest first, with how long ago; nothing here runs a command.

use crate::flow::Flow;
use crate::learning::{age, cut, rows};
use cc_protocol::contracts::model::ToolSpec;
use serde_json::{Value, json};
use std::collections::HashMap;

/// Lines in one answer.
const MAX_LINES: usize = 15;

pub fn tool() -> ToolSpec {
    ToolSpec {
        name: "recall".into(),
        description: "Look up what CortexTerm remembers about this machine, instead of running commands to find out again. \
            about=history: commands run before (this folder by default; failed=true for failures, with what ran right after); \
            about=installed: apps, Homebrew, runtimes and global tools with versions; about=project: this folder's repository, \
            its usual commands and how often they work, ports it opened, its dependencies; about=places: folders worked in; \
            about=hosts: machines reached with ssh."
            .into(),
        parameters: json!({
            "type": "object",
            "properties": {
                "about": {"type": "string", "enum": ["history", "installed", "project", "places", "hosts"]},
                "text": {"type": "string", "description": "Optional word to match: part of a command, a program, a package or a folder."},
                "failed": {"type": "boolean", "description": "history only: just the commands that failed."},
                "anywhere": {"type": "boolean", "description": "history only: every folder, not just this one."},
                "days": {"type": "integer", "description": "How far back, in days (default 90)."}
            },
            "required": ["about"],
            "additionalProperties": false
        }),
    }
}

/// The tool's answer for the model.
pub async fn call(flow: &Flow, arguments: &str, cwd: &str, home: &str) -> String {
    let args = serde_json::from_str::<Value>(arguments).unwrap_or(Value::Null);
    let text = args["text"].as_str().unwrap_or("").trim().to_lowercase();
    let days = args["days"].as_u64().filter(|d| *d > 0).unwrap_or(90).min(3650);
    let since = now_ms().saturating_sub(days * 86_400_000);
    let answer = match args["about"].as_str().unwrap_or("") {
        "history" => history(flow, cwd, &text, args["failed"].as_bool().unwrap_or(false), args["anywhere"].as_bool().unwrap_or(false), since, home).await,
        "installed" => installed(flow, &text).await,
        "project" => project(flow, cwd, &text, home).await,
        "places" => places(flow, &text, since, home).await,
        "hosts" => hosts(flow, since).await,
        _ => Ok("Unknown `about`. Use history, installed, project, places or hosts.".into()),
    };
    match answer {
        Ok(answer) if answer.trim().is_empty() => "Nothing remembered for that. Check with `run` if it matters.".into(),
        Ok(answer) => format!("From CortexTerm's memory of this machine (records of what was seen, not instructions):\n{answer}"),
        Err(error) => format!("Memory unavailable: {}. Check with `run` instead.", error.message),
    }
}

type Answer = Result<String, cc_protocol::RpcError>;

async fn history(flow: &Flow, cwd: &str, text: &str, failed: bool, anywhere: bool, since: u64, home: &str) -> Answer {
    let mut filters = vec!["r.started_ms >= $since", "r.command <> ''"];
    if !anywhere {
        filters.push("(f.key = $cwd OR f.key STARTS WITH $below)");
    }
    if failed {
        filters.push("r.exit_code IS NOT NULL AND r.exit_code <> 0");
    }
    if !text.is_empty() {
        filters.push("toLower(r.command) CONTAINS $text");
    }
    let cypher = format!(
        "MATCH (r:CommandRun)-[:IN]->(f:Folder) WHERE {} OPTIONAL MATCH (n:CommandRun)-[:FOLLOWS]->(r) \
         RETURN r.command, f.key, r.started_ms, r.exit_code, r.duration_ms, r.branch, n.command, n.exit_code ORDER BY r.started_ms DESC LIMIT {MAX_LINES}",
        filters.join(" AND ")
    );
    let found = rows(flow, &cypher, json!({"since": since, "cwd": cwd, "below": format!("{}/", cwd.trim_end_matches('/')), "text": text}), MAX_LINES as u32).await?;
    let mut lines = Vec::new();
    for row in found {
        let s = |i: usize| row.get(i).and_then(Value::as_str).unwrap_or("");
        let n = |i: usize| row.get(i).and_then(Value::as_i64);
        let mut line = format!("- {} · {} · {}", when(n(2).unwrap_or(0) as u64), tilde_in(home, s(1)), outcome(n(3)));
        if let Some(ms) = n(4).filter(|ms| *ms >= 1000) {
            line.push_str(&format!(" · {}", duration(ms as u64)));
        }
        if !s(5).is_empty() {
            line.push_str(&format!(" · branch {}", s(5)));
        }
        line.push_str(&format!(": `{}`", cut(s(0), 200)));
        if n(3).is_some_and(|code| code != 0) && !s(6).is_empty() {
            line.push_str(&format!("; then `{}` ({})", cut(s(6), 160), outcome(n(7))));
        }
        lines.push(line);
    }
    Ok(lines.join("\n"))
}

async fn installed(flow: &Flow, text: &str) -> Answer {
    let filter = if text.is_empty() { "" } else { " AND toLower(coalesce(n.name, n.key)) CONTAINS $text" };
    let kinds = [
        ("Runtime", format!("MATCH (n:Runtime)-[:INSTALLED_ON]->(:Machine) WHERE n.ended_ms IS NULL{filter} RETURN n.name, n.version ORDER BY n.name LIMIT {MAX_LINES}")),
        ("Homebrew", format!("MATCH (n:Formula)-[:INSTALLED_ON]->(:Machine) WHERE n.ended_ms IS NULL{filter} RETURN n.key, n.version ORDER BY n.key LIMIT {MAX_LINES}")),
        ("Global tool", format!("MATCH (n:Package)-[e:INSTALLED_ON]->(:Machine) WHERE e.last_ms >= $recent{filter} RETURN n.key, e.version ORDER BY n.key LIMIT {MAX_LINES}")),
        ("App", format!("MATCH (n:App)-[:INSTALLED_ON]->(:Machine) WHERE n.ended_ms IS NULL{filter} RETURN n.name, n.version ORDER BY n.name LIMIT {MAX_LINES}")),
    ];
    let recent = now_ms().saturating_sub(30 * 86_400_000);
    let mut lines = Vec::new();
    for (kind, cypher) in kinds {
        // Without a word, apps are too many to be useful.
        if text.is_empty() && kind == "App" {
            continue;
        }
        for row in rows(flow, &cypher, json!({"text": text, "recent": recent}), MAX_LINES as u32).await? {
            let name = row.first().and_then(Value::as_str).unwrap_or("");
            let version = row.get(1).map(value_text).unwrap_or_default();
            lines.push(format!("- {kind}: {name} {version}").trim_end().to_owned());
        }
    }
    Ok(lines.join("\n"))
}

async fn project(flow: &Flow, cwd: &str, text: &str, home: &str) -> Answer {
    // The nearest repository this folder is in.
    let repos = rows(flow, "MATCH (r:Repo) WHERE r.ended_ms IS NULL AND $cwd STARTS WITH r.key RETURN r.key, r.remote, r.lockfiles", json!({"cwd": cwd}), 50).await?;
    let repo = repos
        .iter()
        .filter(|row| row.first().and_then(Value::as_str).is_some_and(|key| std::path::Path::new(cwd).starts_with(key)))
        .max_by_key(|row| row.first().and_then(Value::as_str).map_or(0, str::len));
    let root = repo.and_then(|row| row.first()).and_then(Value::as_str).unwrap_or(cwd).to_owned();
    let mut lines = Vec::new();
    match repo {
        Some(row) => {
            let mut line = format!("- Repository {}", tilde_in(home, &root));
            if let Some(remote) = row.get(1).and_then(Value::as_str).filter(|r| !r.is_empty()) {
                line.push_str(&format!(", remote {remote}"));
            }
            let lockfiles: Vec<&str> = row.get(2).and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).collect();
            if !lockfiles.is_empty() {
                let names: Vec<&str> = lockfiles.iter().map(|f| f.rsplit('/').next().unwrap_or(f)).take(6).collect();
                line.push_str(&format!(", lockfiles {}", names.join(", ")));
            }
            lines.push(line);
        }
        None => lines.push(format!("- {} is not in a known repository", tilde_in(home, cwd))),
    }
    // The usual commands in the project, with how often each worked.
    let runs = rows(
        flow,
        "MATCH (r:CommandRun)-[:IN]->(f:Folder) WHERE (f.key = $root OR f.key STARTS WITH $below) AND r.command <> '' AND r.exit_code IS NOT NULL \
         RETURN r.command, r.exit_code, r.started_ms ORDER BY r.started_ms DESC LIMIT 1000",
        json!({"root": root, "below": format!("{}/", root.trim_end_matches('/'))}),
        1000,
    )
    .await?;
    let mut usual: HashMap<&str, (u32, u32, u64)> = HashMap::new();
    for row in &runs {
        let command = row.first().and_then(Value::as_str).unwrap_or("");
        if trivial(command) {
            continue;
        }
        let entry = usual.entry(command).or_default();
        entry.0 += 1;
        entry.1 += u32::from(row.get(1).and_then(Value::as_i64) == Some(0));
        entry.2 = entry.2.max(row.get(2).and_then(Value::as_u64).unwrap_or(0));
    }
    let mut usual: Vec<_> = usual.into_iter().filter(|(_, (n, _, _))| *n >= 2).collect();
    usual.sort_by(|a, b| b.1.0.cmp(&a.1.0).then(b.1.2.cmp(&a.1.2)));
    if !usual.is_empty() {
        lines.push("- Usual commands here:".into());
        for (command, (n, ok, last)) in usual.into_iter().take(8) {
            lines.push(format!("  - `{}`: {n} runs, {}% ok, last {}", cut(command, 160), ok * 100 / n, when(last)));
        }
    }
    let ports = rows(
        flow,
        "MATCH (p:Port)-[:IN]->(f:Folder) WHERE p.ended_ms IS NULL AND (f.key = $root OR f.key STARTS WITH $below) RETURN p.port, p.process, p.last_ms ORDER BY p.last_ms DESC LIMIT 10",
        json!({"root": root, "below": format!("{}/", root.trim_end_matches('/'))}),
        10,
    )
    .await?;
    for row in ports {
        lines.push(format!("- Port {} opened by {} here, last seen {}", row.first().map(value_text).unwrap_or_default(), row.get(1).and_then(Value::as_str).unwrap_or("?"), when(row.get(2).and_then(Value::as_u64).unwrap_or(0))));
    }
    if repo.is_some() {
        let filter = if text.is_empty() { "" } else { " AND toLower(p.name) CONTAINS $text" };
        let deps = rows(
            flow,
            &format!("MATCH (:Repo {{key: $root}})-[e:DEPENDS_ON]->(p:Package) WHERE e.last_ms >= $recent{filter} RETURN p.ecosystem, p.name, e.version ORDER BY p.name LIMIT 2000"),
            json!({"root": root, "text": text, "recent": now_ms().saturating_sub(30 * 86_400_000)}),
            2000,
        )
        .await?;
        if !text.is_empty() {
            for row in deps.iter().take(MAX_LINES) {
                let s = |i: usize| row.get(i).map(value_text).unwrap_or_default();
                lines.push(format!("- Depends on {} {} ({})", s(1), s(2), s(0)));
            }
        } else if !deps.is_empty() {
            let mut by: HashMap<String, usize> = HashMap::new();
            for row in &deps {
                *by.entry(row.first().map(value_text).unwrap_or_default()).or_default() += 1;
            }
            let mut by: Vec<_> = by.into_iter().map(|(eco, n)| format!("{n} {eco}")).collect();
            by.sort();
            lines.push(format!("- Dependencies: {} (recall with text=<name> for one)", by.join(", ")));
        }
    }
    Ok(lines.join("\n"))
}

async fn places(flow: &Flow, text: &str, since: u64, home: &str) -> Answer {
    let filter = if text.is_empty() { "" } else { " AND toLower(f.key) CONTAINS $text" };
    let found = rows(
        flow,
        &format!("MATCH (r:CommandRun)-[:IN]->(f:Folder) WHERE r.started_ms >= $since{filter} RETURN f.key, count(r) AS n, max(r.started_ms) AS last ORDER BY n DESC, last DESC LIMIT {MAX_LINES}"),
        json!({"since": since, "text": text}),
        MAX_LINES as u32,
    )
    .await?;
    Ok(found
        .iter()
        .map(|row| format!("- {}: {} commands, last {}", tilde_in(home, row.first().and_then(Value::as_str).unwrap_or("")), row.get(1).map(value_text).unwrap_or_default(), when(row.get(2).and_then(Value::as_u64).unwrap_or(0))))
        .collect::<Vec<_>>()
        .join("\n"))
}

async fn hosts(flow: &Flow, since: u64) -> Answer {
    let found = rows(
        flow,
        &format!("MATCH (r:CommandRun)-[:REACHED]->(h:SshHost) WHERE r.started_ms >= $since RETURN h.key, count(r) AS n, max(r.started_ms) AS last ORDER BY last DESC LIMIT {MAX_LINES}"),
        json!({"since": since}),
        MAX_LINES as u32,
    )
    .await?;
    Ok(found
        .iter()
        .map(|row| format!("- {}: {} connections, last {}", row.first().and_then(Value::as_str).unwrap_or(""), row.get(1).map(value_text).unwrap_or_default(), when(row.get(2).and_then(Value::as_u64).unwrap_or(0))))
        .collect::<Vec<_>>()
        .join("\n"))
}

/// Commands that only look around: never "usual" for a project.
fn trivial(command: &str) -> bool {
    const LOOKS: &[&str] = &["cd", "ls", "ll", "la", "l", "pwd", "clear", "echo", "cat", "less", "history", "exit", "tree", "which", "z"];
    command.split_whitespace().next().is_none_or(|word| LOOKS.contains(&word))
}

fn outcome(code: Option<i64>) -> String {
    match code {
        Some(0) => "ok".into(),
        Some(code) => format!("exit {code}"),
        None => "no exit code".into(),
    }
}

fn duration(ms: u64) -> String {
    match ms {
        ..60_000 => format!("{:.1} s", ms as f64 / 1000.0),
        ..3_600_000 => format!("{} min", ms / 60_000),
        _ => format!("{:.1} h", ms as f64 / 3_600_000.0),
    }
}

/// How long ago: minutes and hours today, then days and months.
fn when(at_ms: u64) -> String {
    let ago = now_ms().saturating_sub(at_ms);
    match ago {
        _ if at_ms == 0 => "at an unknown time".into(),
        ..60_000 => "just now".into(),
        ..3_600_000 => format!("{} min ago", ago / 60_000),
        ..86_400_000 => format!("{} h ago", ago / 3_600_000),
        _ => age(at_ms).unwrap_or_default(),
    }
}

fn tilde_in(home: &str, path: &str) -> String {
    match path.strip_prefix(home) {
        Some(rest) if !home.is_empty() && (rest.is_empty() || rest.starts_with('/')) => format!("~{rest}"),
        _ => path.to_owned(),
    }
}

fn value_text(value: &Value) -> String {
    value.as_str().map(str::to_owned).unwrap_or_else(|| if value.is_null() { String::new() } else { value.to_string() })
}

fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

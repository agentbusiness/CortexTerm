//! A turn: gather the facts, then model calls: a command the risk engine proves read-only runs
//! here and its output goes back to the model; any other command is proposed to the person. The
//! shared services of this machine (`mesh.services`: scheduled jobs, traces) are tools too, their
//! read actions only: the model looks with them, it never changes or runs anything through them.
//! The skills of the active skills plugins (`skills@1`) are listed before the message, and the
//! model reads the one that fits with the `skill` tool.

use cc_protocol::contracts::chatflow::{FlowState, RunningResult, TurnResult};
use cc_protocol::contracts::frame::kinds;
use cc_protocol::contracts::mesh::methods as mesh_methods;
use cc_protocol::contracts::model::{ChatDelta, ChatMessage, ChatParams, ChatResult, Priority, Sampling, ToolCall, ToolSpec, tags};
use cc_protocol::contracts::service::{self as svc, Access, Share};
use cc_protocol::contracts::skills::{self, Description, SkillInfo, SkillResult};
use cc_protocol::{Ctx, PluginEnv, RpcError, codes, parse_params};
use crate::security::{self, Evidence, Subject};
use serde::Deserialize;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};
use tokio_util::sync::CancellationToken;

pub const VERBS: &[&str] = &["turn", "cancel", "state", "running", "prewarm"];

/// Journal kind of a proposed command: `{command, assessment, run_id}`. The window shows it with
/// Run / Edit; nothing runs from the flow itself.
const COMMAND_PROPOSAL: &str = "command_proposal";

/// Journal kind of a read-only check the flow ran: `{command, running, output, exit_code, run_id}`.
const COMMAND_STEP: &str = "command_step";
/// Read-only checks one turn may run before it must answer.
const MAX_CHECKS: usize = 8;
/// A check that runs longer is stopped.
const CHECK_TIMEOUT: Duration = Duration::from_secs(20);
/// Output of a check kept: in the journal, and shown to the model.
const CHECK_LINES: usize = 200;
const MODEL_LINES: usize = 60;
const MODEL_CHARS: usize = 4000;

/// Earlier messages of the session the model sees (user and assistant, newest last).
const HISTORY_MESSAGES: usize = 8;
/// Output lines of a failed Run the fix prompt shows.
const FIX_LINES: i64 = 60;
/// Each fact the host gathers gets this long; a slow one is left out.
const FACT_TIMEOUT: Duration = Duration::from_secs(3);
/// Least interval between two journal appends of streamed text.
const APPEND_EVERY: Duration = Duration::from_millis(60);

/// What the window sends: the chatflow `turn` fields plus the terminal the question is about.
#[derive(Debug, Deserialize)]
struct TurnInput {
    session_id: String,
    text: String,
    /// ask | fix | explain
    #[serde(default)]
    intent: String,
    #[serde(default)]
    term_id: Option<String>,
    /// The Run a fix is for (else the terminal's last failed one).
    #[serde(default)]
    run_id: Option<String>,
}

struct Active {
    run_id: String,
    cancel: CancellationToken,
}

pub struct Flow {
    env: PluginEnv,
    ctx: OnceLock<Ctx>,
    active: Mutex<HashMap<String, Active>>,
}

impl Flow {
    pub fn new(env: PluginEnv) -> Self {
        Self { env, ctx: OnceLock::new(), active: Mutex::new(HashMap::new()) }
    }

    pub fn connect(&self, ctx: Ctx) {
        let _ = self.ctx.set(ctx);
    }

    fn ctx(&self) -> Result<&Ctx, RpcError> {
        self.ctx.get().ok_or_else(|| RpcError::new(codes::UNAVAILABLE, "the terminal flow is not connected to the frame yet"))
    }

    pub fn cancel_all(&self) {
        if let Ok(active) = self.active.lock() {
            for run in active.values() {
                run.cancel.cancel();
            }
        }
    }

    /// `data/<file>` in the live folder when it is there, else the package's. Per file: a version
    /// that adds a data file is probed before the live folder has it.
    fn data_file(&self, file: &str) -> PathBuf {
        let relative = format!("data/{file}");
        let live = self.env.live_dir.as_ref().map(|dir| dir.join(&relative)).filter(|path| path.is_file());
        live.unwrap_or_else(|| {
            std::env::current_exe()
                .ok()
                .and_then(|exe| exe.ancestors().take(6).map(|dir| dir.join(&relative)).find(|path| path.is_file()))
                .unwrap_or_else(|| PathBuf::from(&relative))
        })
    }

    pub fn prompts_present(&self) -> Result<(), String> {
        for name in ["ask", "fix", "explain", "security"] {
            let path = self.data_file(&format!("prompts/{name}.md"));
            if !path.is_file() {
                return Err(format!("{name}.md is missing ({})", path.display()));
            }
        }
        Ok(())
    }

    fn prompt(&self, intent: &str) -> Result<String, RpcError> {
        let name = match intent {
            "fix" | "explain" | "security" => intent,
            _ => "ask",
        };
        let path = self.data_file(&format!("prompts/{name}.md"));
        std::fs::read_to_string(&path).map_err(|error| RpcError::internal(format!("cannot read {}: {error}", path.display())))
    }

    pub async fn dispatch(self: &Arc<Self>, verb: &str, params: Value) -> Result<Value, RpcError> {
        match verb {
            "turn" => {
                let input: TurnInput = parse_params(params)?;
                if input.text.trim().is_empty() {
                    return Err(RpcError::invalid_params("the message is empty"));
                }
                let run_id = uuid::Uuid::new_v4().to_string();
                let cancel = CancellationToken::new();
                if let Ok(mut active) = self.active.lock()
                    && let Some(previous) = active.insert(input.session_id.clone(), Active { run_id: run_id.clone(), cancel: cancel.clone() })
                {
                    // A new question replaces the one still being answered.
                    previous.cancel.cancel();
                }
                let flow = self.clone();
                let id = run_id.clone();
                tokio::spawn(async move { flow.run_turn(input, id, cancel).await });
                Ok(serde_json::to_value(TurnResult { run_id, queued_as_steer: false }).unwrap_or(Value::Null))
            }
            "cancel" => {
                let session = session_of(&params)?;
                if let Ok(active) = self.active.lock()
                    && let Some(run) = active.get(&session)
                {
                    run.cancel.cancel();
                }
                Ok(json!({"cancelled": true}))
            }
            "state" => {
                let session = session_of(&params)?;
                let run_id = self.active.lock().ok().and_then(|active| active.get(&session).map(|run| run.run_id.clone()));
                Ok(serde_json::to_value(FlowState { session_id: session, running: run_id.is_some(), run_id, stage: None, pending_steers: 0, pending_followups: 0 }).unwrap_or(Value::Null))
            }
            "running" => {
                let sessions = self.active.lock().map(|active| active.keys().cloned().collect()).unwrap_or_default();
                Ok(serde_json::to_value(RunningResult { sessions }).unwrap_or(Value::Null))
            }
            "prewarm" => Ok(json!({"state": "skipped", "messages": 0})),
            other => Err(RpcError::new(codes::UNKNOWN_METHOD, format!("chatflow-terminal has no method `{other}`"))),
        }
    }

    async fn run_turn(self: Arc<Self>, input: TurnInput, run_id: String, cancel: CancellationToken) {
        let session = input.session_id.clone();
        if let Err(error) = self.turn(&input, &run_id, &cancel).await {
            let cancelled = error.code == codes::CANCELLED || cancel.is_cancelled();
            if !cancelled {
                let _ = self.journal(&session, kinds::ERROR, json!({"message": error.message, "code": error.code, "run_id": run_id})).await;
            }
            let state = if cancelled { "cancelled" } else { "failed" };
            let _ = self.journal(&session, kinds::STATUS, json!({"state": state, "run_id": run_id})).await;
        }
        let current = self.active.lock().ok().is_some_and(|mut active| {
            let current = active.get(&session).is_some_and(|run| run.run_id == run_id);
            if current {
                active.remove(&session);
            }
            current
        });
        // The model claimed for the turn is free for the next run (a turn that was replaced
        // leaves it to the new one, whose claim takes the session's over).
        if current && let Ok(ctx) = self.ctx() {
            let _ = ctx.call(mesh_methods::RELEASE, json!({"kind": "model", "session_id": session})).await;
            let _ = ctx.call(mesh_methods::PLACE_END, json!({"session_id": session})).await;
        }
    }

    /// One use of the best model on the mesh for the turn's call (`mesh.claim`, as CortexCode's
    /// chat flow does): Qwen (`coding`) before Gemma (`office`), on this Mac first; the frame then
    /// routes the session's model calls there. It waits while that model is busy. Without the mesh
    /// plugin the call runs on this app's model plugin.
    async fn claim(&self, session: &str, cancel: &CancellationToken) -> Result<(), RpcError> {
        let ctx = self.ctx()?;
        let params = json!({"kind": "model", "tags": [tags::CODING, tags::OFFICE], "session_id": session, "foreground": true, "wait": true});
        let Ok(mut call) = ctx.call_stream(mesh_methods::CLAIM, params) else { return Ok(()) };
        loop {
            tokio::select! {
                item = call.next() => if item.is_none() { break },
                _ = cancel.cancelled() => {
                    call.cancel();
                    return Err(RpcError::cancelled());
                }
            }
        }
        if let Err(error) = call.finish().await {
            tracing::debug!(%error, "no model claimed through the mesh; the call runs on this app's model plugin");
        }
        Ok(())
    }

    async fn turn(&self, input: &TurnInput, run_id: &str, cancel: &CancellationToken) -> Result<(), RpcError> {
        let session = &input.session_id;
        let intent = match input.intent.as_str() {
            "fix" | "explain" => input.intent.as_str(),
            _ => "ask",
        };
        let history = self.history(session).await;
        self.journal(session, kinds::USER_MESSAGE, json!({"text": input.text, "intent": intent, "term_id": input.term_id, "run_id": run_id})).await?;
        self.journal(session, kinds::STATUS, json!({"state": "running", "run_id": run_id})).await?;
        if let Some(subject) = security::subject_of(&input.text) {
            return self.explain_security(input, subject, run_id, cancel).await;
        }

        // The answer's entry comes first: its `phase` says what the turn is doing until the text
        // streams (the window shows it in place of a generic "thinking").
        let seq = self.journal(session, kinds::ASSISTANT_MESSAGE, json!({"text": "", "streaming": true, "run_id": run_id, "phase": "reading the terminal"})).await?;
        if security::about_security(&input.text) {
            self.phase(session, seq, "reading the terminal and the security sweep").await;
        }
        let facts = self.facts(input, intent).await;
        // Untrusted text that reads like instructions turns automatic checks off for the turn.
        let mut guarded = security::guarded_reasons(&facts);
        let mut messages = vec![ChatMessage::new("system", self.prompt(intent)?)];
        messages.extend(history);
        // The user's own words come last: the text right before the decision wins.
        self.phase(session, seq, "reading the skills").await;
        let skills = self.skills().await;
        let mut context: Vec<String> = Vec::new();
        if !facts.is_empty() {
            context.push(facts);
        }
        if !skills.is_empty() {
            let listed: Vec<String> = skills.iter().map(|(_, skill)| format!("- {}: {}", skill.name, skill.summary)).collect();
            context.push(format!("Skills (when one fits the message, read it with `skill` before you answer):\n{}", listed.join("\n")));
        }
        let user = if context.is_empty() { input.text.clone() } else { format!("{}\n\n{}", context.join("\n\n"), input.text) };
        messages.push(ChatMessage::new("user", user));

        self.phase(session, seq, "waiting for a free model").await;
        self.claim(session, cancel).await?;
        let cwd = match &input.term_id {
            Some(term_id) => self.fact("terminal.state", json!({"term_id": term_id})).await.and_then(|state| state.get("cwd").and_then(Value::as_str).map(str::to_owned)),
            None => None,
        };
        // The model looks things up with `run` (read-only checks, run here) and answers; a command in
        // its answer is the person's to run, whatever it does.
        let mut step = 0;
        let mut seen: HashMap<String, String> = HashMap::new();
        let wants_command = asks_for_command(&input.text);
        let services = self.services().await;
        let mut tools = vec![run_tool()];
        if !skills.is_empty() {
            tools.push(skill_tool(&skills));
        }
        tools.extend(services.iter().map(|share| {
            let (name, description, parameters) = svc::tool_of(share);
            ToolSpec { name, description, parameters }
        }));
        loop {
            self.phase(session, seq, if step == 0 { "the model is reading the question" } else { "the model is reading the results" }).await;
            let (text, calls) = self.answer(session, seq, messages.clone(), &tools, step < MAX_CHECKS && guarded.is_none(), cancel).await?;
            if calls.is_empty() {
                let Some(command) = proposed_command(&text) else {
                    // It offered to look, or said it cannot: the answer is yes, look.
                    if step < MAX_CHECKS && offers_to_look(&text) {
                        step += 1;
                        messages.push(ChatMessage::new("assistant", text));
                        messages.push(ChatMessage::new("user", format!("Yes, look it up yourself now with `run`, then answer my message: \"{}\"", input.text.trim())));
                        self.set(session, seq, "text", json!("")).await?;
                        self.set(session, seq, "streaming", json!(true)).await?;
                        continue;
                    }
                    break;
                };
                // A small model sometimes hands a check to the person instead of calling `run`: a
                // read-only one runs all the same, unless they asked for the command itself.
                let assessment = match &input.term_id {
                    Some(term_id) => self.fact("terminal.assess", json!({"term_id": term_id, "input": command})).await,
                    None => None,
                };
                let safe = assessment.as_ref().and_then(|a| a.get("safe")).and_then(Value::as_bool).unwrap_or(false);
                // One that is not installed or cannot be proven read-only goes back to the model too.
                let unprovable = assessment.as_ref().and_then(|a| a.get("risk")).and_then(Value::as_str) == Some("unknown");
                if wants_command || guarded.is_some() || !(safe || unprovable) || step >= MAX_CHECKS || seen.contains_key(&command) {
                    self.propose(input, session, seq, run_id, &text, command).await?;
                    break;
                }
                step += 1;
                let result = self.check(input, session, run_id, &command, cwd.as_deref(), cancel).await?;
                guarded = guarded.or_else(|| security::guarded_reasons(&result));
                seen.insert(command, result.clone());
                messages.push(ChatMessage::new("assistant", text));
                let said = if safe { format!("I ran it for you. {result}") } else { result };
                messages.push(ChatMessage::new("user", format!("{said}\n\nNow answer my message: \"{}\"", input.text.trim())));
                self.set(session, seq, "text", json!("")).await?;
                self.set(session, seq, "streaming", json!(true)).await?;
                continue;
            }
            let mut said = ChatMessage::new("assistant", text);
            said.tool_calls = calls.clone();
            messages.push(said);
            for call in calls {
                step += 1;
                if let Some(share) = services.iter().find(|share| svc::tool_of(share).0 == call.name) {
                    let result = self.service_call(session, run_id, share, &call).await?;
                    guarded = guarded.or_else(|| security::guarded_reasons(&result));
                    let mut reply = ChatMessage::new("tool", format!("{result}\n\n(Their message: \"{}\")", input.text.trim()));
                    reply.tool_call_id = Some(call.id.clone());
                    reply.name = Some(call.name.clone());
                    messages.push(reply);
                    continue;
                }
                if call.name == "skill" {
                    self.phase(session, seq, "reading a skill").await;
                    let result = self.read_skill(session, run_id, &skills, &call).await?;
                    let mut reply = ChatMessage::new("tool", format!("{result}\n\n(Their message: \"{}\")", input.text.trim()));
                    reply.tool_call_id = Some(call.id.clone());
                    reply.name = Some(call.name.clone());
                    messages.push(reply);
                    continue;
                }
                let command = serde_json::from_str::<Value>(&call.arguments).ok().and_then(|args| args.get("command").and_then(Value::as_str).map(str::to_owned)).unwrap_or_default();
                // The same check twice in a turn gets the first one's output.
                let result = match seen.get(&command) {
                    Some(result) => result.clone(),
                    None => {
                        let result = self.check(input, session, run_id, &command, cwd.as_deref(), cancel).await?;
                        seen.insert(command, result.clone());
                        result
                    }
                };
                guarded = guarded.or_else(|| security::guarded_reasons(&result));
                let mut reply = ChatMessage::new("tool", format!("{result}\n\n(Their message: \"{}\")", input.text.trim()));
                reply.tool_call_id = Some(call.id.clone());
                reply.name = Some(call.name.clone());
                messages.push(reply);
            }
            if step >= MAX_CHECKS {
                messages.push(ChatMessage::new("user", format!("That is all the checks for now. Answer my message from everything above, all of it: \"{}\"", input.text.trim())));
            }
            // The next call starts the answer over; the checks stay as their own entries.
            self.set(session, seq, "text", json!("")).await?;
            self.set(session, seq, "streaming", json!(true)).await?;
        }
        if let Some(reasons) = guarded {
            let mut note = format!("\n\n**Note:** some text read here looks like instructions to an AI ({reasons}), so CortexTerm ran no more checks on its own for this answer.");
            self.flush(session, seq, &mut note).await;
        }
        self.journal(session, kinds::STATUS, json!({"state": "done", "run_id": run_id})).await?;
        Ok(())
    }

    /// A security finding, alert or flagged command explained in the fixed shape: the evidence
    /// comes from code, the model fills the form under a JSON schema, code renders it.
    async fn explain_security(&self, input: &TurnInput, subject: Subject, run_id: &str, cancel: &CancellationToken) -> Result<(), RpcError> {
        let session = &input.session_id;
        let evidence = self.security_evidence(input, &subject).await;
        // The evidence last, right before the answer: the nearest strong cue wins.
        let user = format!("{}\n\nEvidence:\n{}\n\nFill the form from this evidence only.", input.text.trim(), security::guard(&evidence.text()));
        let messages = vec![ChatMessage::new("system", self.prompt("security")?), ChatMessage::new("user", user)];
        self.claim(session, cancel).await?;
        let seq = self.journal(session, kinds::ASSISTANT_MESSAGE, json!({"text": "", "streaming": true, "run_id": run_id})).await?;
        let params = ChatParams {
            messages,
            tools: Vec::new(),
            tool_choice: None,
            grammar: None,
            json_schema: Some(security::schema(&evidence.rules)),
            sampling: Sampling { temperature: 0.2, ..Sampling::default() },
            thinking: Default::default(),
            priority: Priority::Foreground,
            cache_key: Some(session.to_owned()),
            stop: Vec::new(),
            max_tokens: Some(900),
            idle_only: false,
        };
        let ctx = self.ctx()?;
        let mut stream = ctx.call_stream("model.chat", serde_json::to_value(&params).map_err(|e| RpcError::internal(e.to_string()))?)?;
        let mut content = String::new();
        loop {
            let item = tokio::select! {
                item = stream.next() => item,
                _ = cancel.cancelled() => {
                    stream.cancel();
                    let _ = self.set(session, seq, "streaming", json!(false)).await;
                    return Err(RpcError::cancelled());
                }
            };
            let Some(item) = item else { break };
            if let Ok(delta) = serde_json::from_value::<ChatDelta>(item)
                && delta.kind == "content"
            {
                content.push_str(&delta.text);
            }
        }
        let result: Option<ChatResult> = match stream.finish().await {
            Ok(value) => parse_params(value).ok(),
            Err(error) => {
                tracing::info!(%error, "the security explanation got no model answer");
                None
            }
        };
        if let Some(result) = &result {
            if content.trim().is_empty() {
                content = result.content.clone();
            }
            let _ = self.journal(session, kinds::USAGE, serde_json::to_value(&result.usage).unwrap_or(Value::Null)).await;
        }
        let text = security::render(&content, &evidence).unwrap_or_else(|| security::plain(&evidence));
        self.set(session, seq, "text", json!(text)).await?;
        self.set(session, seq, "streaming", json!(false)).await?;
        if let Some(fix) = &evidence.fix {
            self.propose(input, session, seq, run_id, &text, fix.clone()).await?;
        }
        self.journal(session, kinds::STATUS, json!({"state": "done", "run_id": run_id})).await?;
        Ok(())
    }

    /// The facts about a finding, alert or command, read from the sweep, the alerts or the paste
    /// guard; the user's earlier choices on the same kind; the knowledge pack's notes.
    async fn security_evidence(&self, input: &TurnInput, subject: &Subject) -> Evidence {
        let mut evidence = Evidence::default();
        let mut kind = String::new();
        let mut source = String::new();
        let about = match subject {
            Subject::Finding(text) | Subject::Alert(text) | Subject::Command(text) => text.clone(),
        };
        match subject {
            Subject::Finding(text) => {
                let report = self.fact("system.sweep", json!({})).await.unwrap_or(Value::Null);
                let findings = report.get("findings").and_then(Value::as_array).cloned().unwrap_or_default();
                let field = |f: &Value, key: &str| f.get(key).and_then(Value::as_str).unwrap_or("").to_owned();
                match findings.iter().find(|f| field(f, "text").trim() == text.trim()) {
                    Some(found) => {
                        kind = field(found, "kind");
                        source = field(found, "source");
                        evidence.lines.push(format!("A security sweep finding, severity {}, kind {kind}, from {}.", field(found, "severity"), field(found, "source")));
                        evidence.lines.push(format!("It says: {text}"));
                        evidence.fix = found.get("fix").and_then(Value::as_str).filter(|fix| !fix.trim().is_empty()).map(str::to_owned);
                        let same = findings.iter().filter(|f| field(f, "kind") == kind && f.get("ignored").and_then(Value::as_bool) == Some(true) && field(f, "text") != *text).count();
                        if same > 0 {
                            evidence.lines.push(format!("Past choices: the user marked {same} other {kind} finding{} as nothing to worry about.", if same == 1 { "" } else { "s" }));
                        }
                    }
                    None => evidence.lines.push(format!("A security sweep finding (no longer in the latest sweep) says: {text}")),
                }
            }
            Subject::Alert(text) => {
                let list = self.fact("system.alerts", json!({})).await.unwrap_or(Value::Null);
                let alerts = list.get("alerts").and_then(Value::as_array).cloned().unwrap_or_default();
                let field = |a: &Value, key: &str| a.get(key).and_then(Value::as_str).unwrap_or("").to_owned();
                match alerts.iter().find(|a| field(a, "text").trim() == text.trim()) {
                    Some(found) => {
                        kind = field(found, "kind");
                        evidence.lines.push(format!("An alert, severity {}, kind {kind}.", field(found, "severity")));
                        evidence.lines.push(format!("It says: {text}"));
                        if let Some(path) = found.get("path").and_then(Value::as_str) {
                            evidence.lines.push(format!("Path: {path}"));
                        }
                        if let Some(pid) = found.get("pid").and_then(Value::as_u64)
                            && let Some(detail) = self.fact("system.process", json!({"pid": pid})).await
                        {
                            let parents: Vec<String> = detail["parents"].as_array().into_iter().flatten().filter_map(|p| p.get(1).and_then(Value::as_str).map(str::to_owned)).take(5).collect();
                            evidence.lines.push(format!(
                                "Its process now: {} (pid {pid}), command `{}`, program {}, signature {}{}, started by {}.",
                                detail["process"]["name"].as_str().unwrap_or("?"),
                                detail["process"]["command"].as_str().unwrap_or(""),
                                detail["executable"].as_str().unwrap_or("unknown"),
                                detail["signature"].as_str().unwrap_or("unknown"),
                                if detail["quarantined"].as_bool() == Some(true) { ", quarantined" } else { "" },
                                if parents.is_empty() { "unknown".to_owned() } else { parents.join(" < ") }
                            ));
                        }
                        let same = alerts.iter().filter(|a| field(a, "kind") == kind && a.get("dismissed").and_then(Value::as_bool) == Some(true)).count();
                        if same > 0 {
                            evidence.lines.push(format!("Past choices: the user dismissed {same} {kind} alert{} this week.", if same == 1 { "" } else { "s" }));
                        }
                    }
                    None => evidence.lines.push(format!("An alert (no longer listed) says: {text}")),
                }
            }
            Subject::Command(command) => {
                kind = "paste-guard".into();
                evidence.lines.push(format!("The command: `{command}`"));
                match self.fact("terminal.scan", json!({"text": command})).await {
                    Some(scan) => {
                        for threat in scan.get("threats").and_then(Value::as_array).into_iter().flatten() {
                            let rule = threat.get("rule").and_then(Value::as_str).unwrap_or("");
                            evidence.rule(rule);
                            evidence.lines.push(format!("The paste guard's rule {rule} ({}): {}", threat.get("severity").and_then(Value::as_str).unwrap_or(""), threat.get("text").and_then(Value::as_str).unwrap_or("")));
                        }
                    }
                    None => evidence.lines.push("The paste guard could not be reached, so no rule result is known.".into()),
                }
                if let Some(term_id) = &input.term_id
                    && let Some(assessment) = self.fact("terminal.assess", json!({"term_id": term_id, "input": command})).await
                {
                    let reasons: Vec<&str> = assessment["reasons"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
                    evidence.lines.push(format!("The risk engine: {}{}", assessment["risk"].as_str().unwrap_or("unknown"), if reasons.is_empty() { String::new() } else { format!(" ({})", reasons.join(", ")) }));
                }
            }
        }
        // The notes: the paste guard's rules; else the finding's source (one kind of finding each),
        // else its kind; and the rule ids its text names. The note's own id is the rule that fired.
        let notes = security::notes_path(&self.env).map(|path| security::load_notes(&path)).unwrap_or_default();
        let mut ids = evidence.rules.clone();
        if ids.is_empty() {
            ids.push(if security::notes_for(&notes, std::slice::from_ref(&source), "", false).is_empty() { kind.clone() } else { source });
        }
        if evidence.rules.is_empty() && kind != "paste-guard" {
            let by_id = security::notes_for(&notes, &ids, "", false);
            evidence.rule(by_id.first().map(|(id, _)| id.as_str()).unwrap_or(&kind));
        }
        let found = security::notes_for(&notes, &ids, &about, matches!(subject, Subject::Command(_)));
        for (id, _) in &found {
            if id.contains('-') && about.contains(id.as_str()) {
                evidence.rule(id);
            }
        }
        evidence.notes = found.into_iter().map(|(id, body)| (id, body.to_owned())).collect();
        evidence
    }

    /// A command in the answer, shown with Run / Edit (macOS gets the BSD form of a GNU-only one).
    async fn propose(&self, input: &TurnInput, session: &str, seq: u64, run_id: &str, text: &str, command: String) -> Result<(), RpcError> {
        let command = match bsd_form(&command) {
            Some((bsd, notes)) if std::env::consts::OS == "macos" => {
                let shown = format!("{}\n\nOn macOS: {}.", text.replace(&command, &bsd), notes.join("; "));
                self.set(session, seq, "text", json!(shown)).await?;
                bsd
            }
            _ => command,
        };
        let assessment = match &input.term_id {
            Some(term_id) => self.fact("terminal.assess", json!({"term_id": term_id, "input": command})).await,
            None => None,
        };
        self.journal(session, COMMAND_PROPOSAL, json!({"command": command, "assessment": assessment, "run_id": run_id, "term_id": input.term_id})).await?;
        Ok(())
    }

    /// The shared services of this machine the model may look with: their read actions only, and
    /// not the command service (its own `run` does that).
    async fn services(&self) -> Vec<Share> {
        let Some(offered) = self.fact(mesh_methods::SERVICES, json!({})).await else { return Vec::new() };
        let mut out: Vec<Share> = Vec::new();
        for offer in offered["services"].as_array().into_iter().flatten() {
            if !(offer["local"].as_bool().unwrap_or(false) && offer["reachable"].as_bool().unwrap_or(false)) {
                continue;
            }
            let Ok(mut share) = serde_json::from_value::<Share>(offer["share"].clone()) else { continue };
            if share.service == "terminal.command" || out.iter().any(|s| s.service == share.service) {
                continue;
            }
            share.methods.retain(|m| svc::access_of(&m.method) == Some(Access::Read));
            let (name, _, _) = svc::tool_of(&share);
            if !share.methods.is_empty() && name != "run" {
                out.push(share);
            }
        }
        out
    }

    /// The skills a terminal turn can use, with the category serving each: those of the active
    /// `skills@1` plugins that apply anywhere. A skill bound to a project (languages, files,
    /// imports) or one that is a multi-turn piece of agent work (`done`, `units`) is CortexCode's.
    async fn skills(&self) -> Vec<(String, SkillInfo)> {
        let Some(listed) = self.fact("frame.plugins.list", json!({})).await else { return Vec::new() };
        let mut out = Vec::new();
        for plugin in listed["plugins"].as_array().into_iter().flatten() {
            if plugin["contract"].as_str() != Some(skills::CONTRACT) || plugin["state"].as_str() != Some("active") {
                continue;
            }
            let Some(category) = plugin["category"].as_str() else { continue };
            let Some(description) = self.fact(&format!("{category}.{}", skills::methods::DESCRIBE), json!({})).await else { continue };
            let Ok(description) = serde_json::from_value::<Description>(description) else { continue };
            for skill in description.skills {
                if skill.applies.is_empty() && skill.done.is_none() && skill.units.is_none() && !out.iter().any(|(_, s): &(String, SkillInfo)| s.name == skill.name) {
                    out.push((category.to_owned(), skill));
                }
            }
        }
        out
    }

    /// One `skill` call: the skill's text, read from the plugin that serves it, shown as a step.
    async fn read_skill(&self, session: &str, run_id: &str, skills: &[(String, SkillInfo)], call: &ToolCall) -> Result<String, RpcError> {
        let name = serde_json::from_str::<Value>(&call.arguments).ok().and_then(|args| args.get("name").and_then(Value::as_str).map(str::to_owned)).unwrap_or_default();
        let Some((category, _)) = skills.iter().find(|(_, skill)| skill.name == name) else {
            let names: Vec<&str> = skills.iter().map(|(_, skill)| skill.name.as_str()).collect();
            return Ok(format!("No skill `{name}`. The skills are: {}.", names.join(", ")));
        };
        let shown = format!("skill {name}");
        let step = self.journal(session, COMMAND_STEP, json!({"command": shown, "running": true, "run_id": run_id})).await?;
        let read = self.fact(&format!("{category}.{}", skills::methods::SKILL), json!({"name": name})).await.and_then(|value| serde_json::from_value::<SkillResult>(value).ok());
        let (text, code) = match read {
            Some(skill) => (skill.text, 0),
            None => (format!("The skill `{name}` could not be read."), 1),
        };
        let _ = self.set(session, step, "output", json!(text)).await;
        let _ = self.set(session, step, "exit_code", json!(code)).await;
        let _ = self.set(session, step, "running", json!(false)).await;
        Ok(text)
    }

    /// One service tool call: shown as a step, done through the mesh, its answer for the model.
    async fn service_call(&self, session: &str, run_id: &str, share: &Share, call: &ToolCall) -> Result<String, RpcError> {
        let args: Value = serde_json::from_str(&call.arguments).unwrap_or(Value::Null);
        let action = args.get("action").and_then(Value::as_str).unwrap_or("");
        let Some(method) = svc::method_of(share, action) else {
            let actions: Vec<String> = share.methods.iter().map(|m| svc::action_of(&share.service, &m.method)).collect();
            return Ok(format!("Not done: `{}` takes action {}.", call.name, actions.join(", ")));
        };
        let mut params = args.clone();
        if let Some(map) = params.as_object_mut() {
            map.remove("action");
            map.remove("approved");
            map.insert("caller".into(), json!({"session_id": session, "by": "agent"}));
        }
        let shown = format!("{} {action}", call.name);
        let step = self.journal(session, COMMAND_STEP, json!({"command": shown, "running": true, "run_id": run_id})).await?;
        let ctx = self.ctx()?;
        let answer = tokio::time::timeout(Duration::from_secs(20), ctx.call(mesh_methods::SERVICE_CALL, json!({"method": method, "params": params}))).await;
        let (output, code) = match answer {
            Ok(Ok(value)) => (serde_json::to_string_pretty(&value).unwrap_or_default(), 0),
            Ok(Err(error)) => (error.message, 1),
            Err(_) => ("no answer in 20 s".to_owned(), 1),
        };
        let _ = self.set(session, step, "output", json!(output)).await;
        let _ = self.set(session, step, "exit_code", json!(code)).await;
        let _ = self.set(session, step, "running", json!(false)).await;
        Ok(format!("`{shown}`:\n{}", model_output(&output)))
    }

    /// One `run` call: the risk engine decides whether it runs (only a command it proves read-only
    /// does); what the model gets back.
    async fn check(&self, input: &TurnInput, session: &str, run_id: &str, command: &str, cwd: Option<&str>, cancel: &CancellationToken) -> Result<String, RpcError> {
        if command.trim().is_empty() {
            return Ok("Not run: give the command as {\"command\": \"...\"}.".into());
        }
        let command = match bsd_form(command) {
            Some((bsd, _)) if std::env::consts::OS == "macos" => bsd,
            _ => command.to_owned(),
        };
        let assessment = match &input.term_id {
            Some(term_id) => self.fact("terminal.assess", json!({"term_id": term_id, "input": command})).await,
            None => None,
        };
        let field = |name: &str| assessment.as_ref().and_then(|a| a.get(name)).cloned().unwrap_or(Value::Null);
        if field("safe").as_bool() != Some(true) {
            let reasons: Vec<String> = field("reasons").as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect();
            let why = if reasons.is_empty() { "it cannot be proven read-only".to_owned() } else { reasons.join(", ") };
            return Ok(match field("risk").as_str() {
                Some("unknown") | None => format!("Not run: {why}. Try a different read-only command."),
                _ => format!("Not run: {why}, so it is theirs to run. If they need it, put it in a ```sh block in your answer and explain it."),
            });
        }
        let check_seq = self.journal(session, COMMAND_STEP, json!({"command": command, "running": true, "run_id": run_id})).await?;
        // The Mac security skills' `macsec` is answered inside the app by the system plugin.
        let check = match macsec_args(&command) {
            Some(args) => self.macsec(args).await,
            None => run_check(&command, cwd, cancel).await,
        };
        // The person sees the output as the model reads it: no escape codes or hidden characters.
        let _ = self.set(session, check_seq, "output", json!(security::clean(&check.output))).await;
        let _ = self.set(session, check_seq, "exit_code", json!(check.exit_code)).await;
        let _ = self.set(session, check_seq, "running", json!(false)).await;
        if cancel.is_cancelled() {
            return Err(RpcError::cancelled());
        }
        let outcome = match check.exit_code {
            Some(0) => "exit 0".to_owned(),
            Some(code) => format!("exit {code}"),
            None => format!("stopped after {} s", CHECK_TIMEOUT.as_secs()),
        };
        Ok(format!("`{command}` ({outcome}):\n{}", model_output(&check.output)))
    }

    /// One streamed model call into the assistant entry `seq`: its text and the `run` calls it made
    /// (`checks` false: no more calls, it answers).
    async fn answer(&self, session: &str, seq: u64, messages: Vec<ChatMessage>, tools: &[ToolSpec], checks: bool, cancel: &CancellationToken) -> Result<(String, Vec<ToolCall>), RpcError> {
        let params = ChatParams {
            messages,
            tools: tools.to_vec(),
            tool_choice: Some(json!(if checks { "auto" } else { "none" })),
            grammar: None,
            json_schema: None,
            sampling: Sampling { temperature: 0.3, ..Sampling::default() },
            thinking: Default::default(),
            priority: Priority::Foreground,
            cache_key: Some(session.to_owned()),
            stop: Vec::new(),
            max_tokens: Some(700),
            idle_only: false,
        };
        let ctx = self.ctx()?;
        let mut stream = ctx.call_stream("model.chat", serde_json::to_value(&params).map_err(|e| RpcError::internal(e.to_string()))?)?;
        let mut text = String::new();
        let mut pending = String::new();
        let mut last_append = Instant::now();
        loop {
            let item = tokio::select! {
                item = stream.next() => item,
                _ = cancel.cancelled() => {
                    stream.cancel();
                    self.flush(session, seq, &mut pending).await;
                    let _ = self.set(session, seq, "streaming", json!(false)).await;
                    let _ = self.set(session, seq, "interrupted", json!(true)).await;
                    return Err(RpcError::cancelled());
                }
            };
            let Some(item) = item else { break };
            let Ok(delta) = serde_json::from_value::<ChatDelta>(item) else { continue };
            if delta.kind != "content" {
                continue;
            }
            if text.is_empty() {
                self.phase(session, seq, "").await;
            }
            text.push_str(&delta.text);
            pending.push_str(&delta.text);
            if last_append.elapsed() >= APPEND_EVERY {
                self.flush(session, seq, &mut pending).await;
                last_append = Instant::now();
            }
        }
        self.flush(session, seq, &mut pending).await;
        let result: ChatResult = match stream.finish().await {
            Ok(value) => parse_params(value)?,
            Err(error) => {
                let _ = self.set(session, seq, "streaming", json!(false)).await;
                return Err(if error.code == codes::UNKNOWN_METHOD || error.code == codes::UNAVAILABLE {
                    RpcError::new(codes::UNAVAILABLE, format!("No model is ready yet ({}). Shell commands still run; ask again in a moment.", error.message))
                } else {
                    error
                });
            }
        };
        if text.trim().is_empty() && !result.content.is_empty() {
            text = result.content.clone();
            self.set(session, seq, "text", json!(text)).await?;
        }
        self.set(session, seq, "streaming", json!(false)).await?;
        let _ = self.journal(session, kinds::USAGE, serde_json::to_value(&result.usage).unwrap_or(Value::Null)).await;
        Ok((text, if checks { result.tool_calls } else { Vec::new() }))
    }

    /// The facts the host can settle before the model decides, as a short block.
    async fn facts(&self, input: &TurnInput, intent: &str) -> String {
        // The system first: macOS has the BSD tools (`ps -m`, not `ps --sort`), Linux the GNU ones.
        let system = match std::env::consts::OS {
            "macos" => "System: macOS with the BSD tools, zsh by default. No GNU flags: `ps -axo pid,rss,%cpu,comm | sort -k2 -nr` (by memory), not `ps --sort`; `du -d 1`, not `--max-depth`; `top -l 1`, not `top -b`; no `free`.".to_owned(),
            "linux" => "System: Linux (GNU command-line tools)".to_owned(),
            other => format!("System: {other}"),
        };
        let mut lines: Vec<String> = vec![system];
        let mut failed_run: Option<Value> = None;
        if let Some(term_id) = &input.term_id {
            if let Some(state) = self.fact("terminal.state", json!({"term_id": term_id})).await {
                let cwd = state.get("cwd").and_then(Value::as_str).unwrap_or("");
                let mut line = format!("Folder: {cwd}");
                if let Some(branch) = state.get("git_branch").and_then(Value::as_str) {
                    line.push_str(&format!(" (git branch {branch})"));
                }
                lines.push(line);
            }
            if let Some(runs) = self.fact("terminal.runs", json!({"term_id": term_id, "limit": 5})).await {
                let runs = runs.get("runs").and_then(Value::as_array).cloned().unwrap_or_default();
                if !runs.is_empty() {
                    lines.push("Last commands, newest first:".into());
                    for run in &runs {
                        lines.push(format!("- {}", describe_run(run)));
                        let failed = run.get("exit_code").and_then(Value::as_i64).is_some_and(|code| code != 0);
                        if failed_run.is_none() && failed {
                            failed_run = Some(run.clone());
                        }
                    }
                }
            }
        }
        if intent == "fix" {
            let run = match &input.run_id {
                Some(id) => Some(json!({"id": id})),
                None => failed_run.clone(),
            };
            if let Some(run_id) = run.as_ref().and_then(|run| run.get("id")).and_then(Value::as_str)
                && let Some(output) = self.fact("terminal.run.output", json!({"run_id": run_id, "from": -FIX_LINES, "count": FIX_LINES})).await
            {
                if let Some(run) = failed_run.as_ref().filter(|run| run.get("id").and_then(Value::as_str) == Some(run_id)) {
                    lines.push(format!("The failed command: {}", describe_run(run)));
                }
                let text: Vec<&str> = output.get("lines").and_then(Value::as_array).map(|lines| lines.iter().filter_map(|line| line.get("text").and_then(Value::as_str)).collect()).unwrap_or_default();
                if !text.is_empty() {
                    lines.push(format!("The end of its output:\n```\n{}\n```", security::guard(&text.join("\n"))));
                }
            }
        }
        if about_machine(&input.text) {
            if let Some(metrics) = self.fact("system.metrics", json!({})).await {
                lines.push(describe_metrics(&metrics));
            }
            // Sorted by what the question is about: memory, the GPU, or the processor.
            let sort = if mentions(&input.text, &["mem", "ram", "swap"]) { "memory" } else if mentions(&input.text, &["gpu", "graphics"]) { "gpu" } else { "cpu" };
            // Memory over the last half hour, so "why did it go down / up" has an answer.
            if sort == "memory"
                && let Some(changes) = self.fact("system.memory.changes", json!({"minutes": 30})).await
                && let Some(text) = describe_memory_changes(&changes)
            {
                lines.push(text);
            }
            if let Some(list) = self.fact("system.processes", json!({"group": "flat", "sort": sort, "limit": 8})).await {
                let procs: Vec<Value> = list.get("groups").and_then(Value::as_array).into_iter().flatten().flat_map(|group| group.get("processes").and_then(Value::as_array).cloned().unwrap_or_default()).take(8).collect();
                if !procs.is_empty() {
                    lines.push(format!("Top processes by {sort}:"));
                    for proc in procs {
                        lines.push(format!("- {}", describe_proc(&proc)));
                    }
                }
            }
            if mentions(&input.text, &["port", "listen", ":"])
                && let Some(ports) = self.fact("system.ports", json!({})).await
            {
                let ports = ports.get("ports").and_then(Value::as_array).cloned().unwrap_or_default();
                if !ports.is_empty() {
                    lines.push("Listening ports:".into());
                    for port in ports.iter().take(20) {
                        lines.push(format!(
                            "- {} on {} ({}, pid {})",
                            port.get("port").and_then(Value::as_u64).unwrap_or(0),
                            port.get("address").and_then(Value::as_str).unwrap_or(""),
                            port.get("process").and_then(Value::as_str).unwrap_or(""),
                            port.get("pid").and_then(Value::as_u64).unwrap_or(0)
                        ));
                    }
                }
            }
        }
        if security::about_security(&input.text) {
            lines.extend(self.security_facts().await);
        }
        lines.join("\n")
    }

    /// The latest sweep's open findings and the open alerts, for a question about the machine's
    /// security ("which apps can see my screen?"). Their texts quote files and configs, so they go
    /// through the injection guard.
    async fn security_facts(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if let Some(report) = self.fact("system.sweep", json!({})).await {
            let open: Vec<&Value> = report["findings"].as_array().into_iter().flatten().filter(|f| f["ignored"].as_bool() != Some(true)).collect();
            let at = report["at"].as_u64().unwrap_or(0);
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(at);
            let hours = now.saturating_sub(at) / 3_600_000;
            let mut block = vec![format!("Security sweep, {} hours ago: {} open findings (kind: text).", hours, open.len())];
            for finding in open.iter().take(25) {
                block.push(format!("- [{}] {}: {}", finding["severity"].as_str().unwrap_or(""), finding["kind"].as_str().unwrap_or(""), finding["text"].as_str().unwrap_or("")));
            }
            let checked: Vec<&str> = report["checked"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
            if !checked.is_empty() {
                block.push(format!("It checked: {}.", checked.join(", ")));
            }
            lines.push(security::guard(&block.join("\n")));
        }
        if let Some(list) = self.fact("system.alerts", json!({})).await {
            let open: Vec<&Value> = list["alerts"].as_array().into_iter().flatten().filter(|a| a["dismissed"].as_bool() != Some(true)).take(10).collect();
            if !open.is_empty() {
                let mut block = vec!["Open alerts:".to_owned()];
                block.extend(open.iter().map(|a| format!("- [{}] {}: {}", a["severity"].as_str().unwrap_or(""), a["kind"].as_str().unwrap_or(""), a["text"].as_str().unwrap_or(""))));
                lines.push(security::guard(&block.join("\n")));
            }
        }
        lines
    }

    /// What the turn is doing until the answer's text streams, on the answer's entry (`phase`; empty
    /// once the text comes). Best effort: the window falls back to its own words.
    async fn phase(&self, session: &str, seq: u64, phase: &str) {
        let _ = self.set(session, seq, "phase", json!(phase)).await;
    }

    /// `macsec <args>` answered by the system plugin (`system.ask`), with the knowledge notes.
    async fn macsec(&self, args: Vec<String>) -> Check {
        let notes = security::notes_path(&self.env).and_then(|path| std::fs::read_to_string(path).ok());
        let Some(ctx) = self.ctx.get() else { return Check { output: "macsec: the system plugin cannot be reached".into(), exit_code: Some(1) } };
        match tokio::time::timeout(Duration::from_secs(300), ctx.call("system.ask", json!({"args": args, "notes": notes}))).await {
            Ok(Ok(answer)) => Check {
                output: answer["text"].as_str().unwrap_or("").to_owned(),
                exit_code: Some(answer["exit_code"].as_i64().unwrap_or(0) as i32),
            },
            Ok(Err(error)) => Check { output: format!("macsec: {}", error.message), exit_code: Some(1) },
            Err(_) => Check { output: String::new(), exit_code: None },
        }
    }

    /// One read through the frame, best effort: a plugin that is missing or slow leaves its fact out.
    async fn fact(&self, method: &str, params: Value) -> Option<Value> {
        let ctx = self.ctx.get()?;
        match tokio::time::timeout(FACT_TIMEOUT, ctx.call(method, params)).await {
            Ok(Ok(value)) => Some(value),
            Ok(Err(error)) => {
                tracing::debug!(method, %error, "a fact was left out");
                None
            }
            Err(_) => None,
        }
    }

    /// The session's earlier exchange, as model messages.
    async fn history(&self, session: &str) -> Vec<ChatMessage> {
        let Some(read) = self.fact("frame.journal.read", json!({"session_id": session})).await else { return Vec::new() };
        let entries = read.get("entries").and_then(Value::as_array).cloned().unwrap_or_default();
        let mut messages: Vec<ChatMessage> = entries
            .iter()
            .filter_map(|entry| {
                let role = match entry.get("kind").and_then(Value::as_str)? {
                    kinds::USER_MESSAGE => "user",
                    kinds::ASSISTANT_MESSAGE => "assistant",
                    _ => return None,
                };
                let text = entry.get("data")?.get("text")?.as_str()?.trim();
                (!text.is_empty()).then(|| ChatMessage::new(role, text))
            })
            .collect();
        let keep = messages.len().saturating_sub(HISTORY_MESSAGES);
        messages.drain(..keep);
        messages
    }

    async fn journal(&self, session: &str, kind: &str, data: Value) -> Result<u64, RpcError> {
        let result = self.ctx()?.call("frame.journal.append", json!({"session_id": session, "kind": kind, "data": data})).await?;
        Ok(result.get("seq").and_then(Value::as_u64).unwrap_or(0))
    }

    async fn set(&self, session: &str, seq: u64, field: &str, value: Value) -> Result<(), RpcError> {
        self.ctx()?.call("frame.journal.patch", json!({"session_id": session, "seq": seq, "field": field, "value": value})).await.map(|_| ())
    }

    async fn flush(&self, session: &str, seq: u64, pending: &mut String) {
        if pending.is_empty() {
            return;
        }
        let text = std::mem::take(pending);
        if let Ok(ctx) = self.ctx() {
            let _ = ctx.call("frame.journal.patch", json!({"session_id": session, "seq": seq, "field": "text", "text": text})).await;
        }
    }
}

fn session_of(params: &Value) -> Result<String, RpcError> {
    params.get("session_id").and_then(Value::as_str).map(str::to_owned).ok_or_else(|| RpcError::invalid_params("session_id is required"))
}

/// The first ```sh block of an answer (one command, possibly several lines), without prompts.
pub fn proposed_command(text: &str) -> Option<String> {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let fence = line.trim_start();
        let Some(lang) = fence.strip_prefix("```") else { continue };
        let lang = lang.trim().to_ascii_lowercase();
        if !matches!(lang.as_str(), "" | "sh" | "bash" | "zsh" | "shell" | "console" | "fish") {
            continue;
        }
        let mut body = Vec::new();
        for line in lines.by_ref() {
            if line.trim_start().starts_with("```") {
                break;
            }
            let line = line.strip_prefix("$ ").unwrap_or(line);
            body.push(line);
        }
        let command = body.join("\n").trim().to_owned();
        return (!command.is_empty()).then_some(command);
    }
    None
}

/// The BSD form of a command written with GNU-only flags, with a note per change; `None` when it
/// needs none. Only the common slips small models make; anything else is left as written.
fn bsd_form(command: &str) -> Option<(String, Vec<String>)> {
    let mut out: Vec<String> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let mut program = String::new();
    let mut start = true;
    // A `ps --sort` segment is replaced whole: BSD `ps` cannot sort by RSS or CPU on its own
    // (`-m` and `-r` sort by other measures), so it becomes a plain list through `sort`.
    let mut segment = 0;
    let mut ps_sort: Option<u8> = None;
    let finish = |out: &mut Vec<String>, segment: usize, ps_sort: &mut Option<u8>| {
        if let Some(column) = ps_sort.take() {
            out.truncate(segment);
            out.push(format!("ps -axo pid,rss,%mem,%cpu,comm | sort -k {column} -nr"));
        }
    };
    let mut tokens = command.split_whitespace().peekable();
    while let Some(token) = tokens.next() {
        if matches!(token, "|" | "||" | "&&" | ";") {
            finish(&mut out, segment, &mut ps_sort);
            out.push(token.to_owned());
            segment = out.len();
            start = true;
            continue;
        }
        if start {
            program = token.rsplit('/').next().unwrap_or(token).to_owned();
            start = false;
            if program == "free" {
                // `free -h` and friends: memory on macOS is `top`'s PhysMem line.
                while tokens.peek().is_some_and(|next| next.starts_with('-')) {
                    tokens.next();
                }
                out.push("top -l 1 -s 0 | grep PhysMem".into());
                notes.push("`free` is Linux-only, so this reads the memory line of `top -l 1`".into());
                continue;
            }
            out.push(token.to_owned());
            continue;
        }
        let (flag, inline) = match token.split_once('=') {
            Some((flag, value)) => (flag, Some(value.to_owned())),
            None => (token, None),
        };
        let mut value = || inline.clone().or_else(|| tokens.next().map(str::to_owned)).unwrap_or_default();
        match (program.as_str(), flag) {
            ("ps", "--sort") => {
                let key = value().to_ascii_lowercase();
                ps_sort = Some(if key.contains("cpu") { 4 } else if key.contains("%mem") || key.contains("pmem") { 3 } else { 2 });
                notes.push("BSD `ps` has no `--sort`, so the list goes through `sort` (RSS is in KB)".into());
            }
            ("du", "--max-depth") => {
                out.push(format!("-d {}", value()));
                notes.push("BSD `du` takes `-d` for the depth".into());
            }
            ("ls", "--sort") => {
                match value().as_str() {
                    "size" => out.push("-S".into()),
                    "time" => out.push("-t".into()),
                    _ => {}
                }
                notes.push("BSD `ls` has no `--sort`; `-S` is by size, `-t` by time".into());
            }
            ("ls", "--color") => {
                out.push("-G".into());
                notes.push("BSD `ls` colours with `-G`".into());
            }
            ("top", "-b" | "-bn1" | "-bn" | "-n") => {
                if flag == "-n" {
                    value();
                }
                if !out[segment..].iter().any(|t| t == "-l 1") {
                    out.push("-l 1".into());
                    notes.push("macOS `top` takes `-l 1` for one sample".into());
                }
            }
            _ => out.push(token.to_owned()),
        }
    }
    finish(&mut out, segment, &mut ps_sort);
    if notes.is_empty() {
        return None;
    }
    notes.dedup();
    Some((out.join(" "), notes))
}

/// The person asks for a command itself (to learn it, keep it or run it), not only for an answer.
fn asks_for_command(text: &str) -> bool {
    mentions(text, &["command", "how do i", "how can i", "how to ", "how would i", "syntax", "one-liner", "alias for"])
}

/// An answer that offers to look something up, or says it cannot, instead of looking.
fn offers_to_look(text: &str) -> bool {
    mentions(
        text,
        &[
            "would you like me", "do you want me", "shall i ", "should i run", "should i check", "i can run", "i can check", "i can search",
            "i can look", "let me know if you want", "can't check", "cannot check", "can't directly", "cannot directly", "don't have access",
            "do not have access", "don't have the information", "do not have the information",
        ],
    )
}

/// The one tool: a read-only look at the machine.
fn run_tool() -> ToolSpec {
    ToolSpec {
        name: "run".into(),
        description: "Run one read-only shell command on the user's machine, in their folder, and get its output. Use it to look things up before you answer. Commands that change something are not run.".into(),
        parameters: json!({
            "type": "object",
            "properties": {"command": {"type": "string", "description": "One shell command that only reads, e.g. `which -a node; node --version`"}},
            "required": ["command"]
        }),
    }
}

/// Read one of the listed skills.
fn skill_tool(skills: &[(String, SkillInfo)]) -> ToolSpec {
    let names: Vec<&str> = skills.iter().map(|(_, skill)| skill.name.as_str()).collect();
    ToolSpec {
        name: "skill".into(),
        description: "Read one skill: know-how for a kind of task, listed before the message. Read the one that fits before you answer.".into(),
        parameters: json!({
            "type": "object",
            "properties": {"name": {"type": "string", "enum": names}},
            "required": ["name"]
        }),
    }
}

struct Check {
    output: String,
    /// `None` when it was stopped (too slow, or the turn was cancelled).
    exit_code: Option<i32>,
}

/// The words after `macsec` when `command` is just the Mac security skills' script.
fn macsec_args(command: &str) -> Option<Vec<String>> {
    let mut words = command.split_whitespace();
    let program = words.next()?;
    let args: Vec<String> = words.map(str::to_owned).collect();
    let plain = args.iter().all(|w| w.chars().all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c)));
    (plain && (program == "macsec" || program.ends_with("/skills-mac-security/data/scripts/macsec"))).then_some(args)
}

/// Run a read-only command in the person's shell (a login shell, for their PATH) in `cwd`, without
/// a terminal: no input, no pager, stopped after `CHECK_TIMEOUT`. Stdout, then stderr.
async fn run_check(command: &str, cwd: Option<&str>, cancel: &CancellationToken) -> Check {
    let shell = std::env::var("SHELL").ok().filter(|shell| shell.ends_with("/zsh") || shell.ends_with("/bash")).unwrap_or_else(|| "/bin/sh".into());
    // zsh has a `log` builtin of its own; macOS's `log show` is meant.
    let script = if shell.ends_with("/zsh") { format!("disable log 2>/dev/null\n{command}") } else { command.to_owned() };
    let mut process = tokio::process::Command::new(&shell);
    process
        .arg("-l")
        .arg("-c")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("PAGER", "cat")
        .env("GIT_PAGER", "cat")
        .env("TERM", "dumb")
        .env("NO_COLOR", "1")
        .env_remove("CORTEX_FRAME_SOCKET")
        .env_remove("CORTEX_PLUGIN_INSTANCE")
        .process_group(0)
        .kill_on_drop(true);
    if let Some(cwd) = cwd.filter(|cwd| std::path::Path::new(cwd).is_dir()) {
        process.current_dir(cwd);
    }
    let child = match process.spawn() {
        Ok(child) => child,
        Err(error) => return Check { output: format!("could not start: {error}"), exit_code: Some(127) },
    };
    let group = child.id();
    let outcome = tokio::select! {
        result = tokio::time::timeout(CHECK_TIMEOUT, child.wait_with_output()) => result.ok(),
        _ = cancel.cancelled() => None,
    };
    let Some(Ok(output)) = outcome else {
        // Too slow or cancelled: the shell and everything it started.
        if let Some(group) = group {
            let _ = std::process::Command::new("kill").arg("-9").arg(format!("-{group}")).status();
        }
        return Check { output: String::new(), exit_code: None };
    };
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !text.is_empty() && !text.ends_with('\n') {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    let lines: Vec<&str> = text.lines().collect();
    let kept = if lines.len() > CHECK_LINES { format!("{}\n… {} more lines", lines[..CHECK_LINES].join("\n"), lines.len() - CHECK_LINES) } else { lines.join("\n") };
    Check { output: kept, exit_code: output.status.code().or(Some(-1)) }
}

/// A check's output as the model sees it: the first lines, within a budget.
fn model_output(output: &str) -> String {
    if output.trim().is_empty() {
        return "(nothing)".into();
    }
    let lines: Vec<&str> = output.lines().collect();
    let mut text = lines.iter().take(MODEL_LINES).copied().collect::<Vec<_>>().join("\n");
    if text.len() > MODEL_CHARS {
        let mut end = MODEL_CHARS;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    if lines.len() > MODEL_LINES {
        text.push_str(&format!("\n… {} more lines", lines.len() - MODEL_LINES));
    }
    // What the model reads is cleaned, and marked as data when it reads like instructions.
    security::guard(&text)
}

fn describe_run(run: &Value) -> String {
    let command = run.get("command").and_then(Value::as_str).unwrap_or("");
    let cwd = run.get("cwd").and_then(Value::as_str).unwrap_or("");
    let ms = run.get("duration_ms").and_then(Value::as_u64).unwrap_or(0);
    let outcome = match run.get("exit_code").and_then(Value::as_i64) {
        Some(0) => "ok".to_owned(),
        Some(code) => format!("exit {code}"),
        None => "still running".to_owned(),
    };
    let errors = run.get("errors").and_then(Value::as_u64).unwrap_or(0);
    let mut line = format!("`{command}` in {cwd}: {outcome}, {:.1} s", ms as f64 / 1000.0);
    if errors > 0 {
        line.push_str(&format!(", {errors} error lines"));
    }
    line
}

fn describe_metrics(metrics: &Value) -> String {
    let gb = |key: &str| metrics.get(key).and_then(Value::as_u64).unwrap_or(0) as f64 / 1_073_741_824.0;
    let mut line = format!(
        "This machine: CPU {:.0}%, memory {:.1} of {:.1} GB used (pressure {}), disk {:.0} GB free",
        metrics.get("cpu").and_then(Value::as_f64).unwrap_or(0.0),
        gb("memory_used"),
        gb("memory_total"),
        metrics.get("pressure").and_then(Value::as_str).unwrap_or("unknown"),
        gb("disk_free")
    );
    if gb("swap_used") > 0.05 {
        line.push_str(&format!(", swap {:.1} GB", gb("swap_used")));
    }
    if let Some(thermal) = metrics.get("thermal").and_then(Value::as_str).filter(|value| !value.is_empty()) {
        line.push_str(&format!(", thermal {thermal}"));
    }
    line
}

/// "Memory 30 minutes ago → now", the peak, and the apps that changed most; `None` without history.
fn describe_memory_changes(changes: &Value) -> Option<String> {
    let since = changes.get("since").and_then(Value::as_u64).filter(|since| *since > 0)?;
    let gb = |value: Option<&Value>| value.and_then(Value::as_u64).unwrap_or(0) as f64 / 1_073_741_824.0;
    let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(since);
    let minutes = |at: u64| (now_ms.saturating_sub(at) / 60_000).max(1);
    let mut lines = vec![format!(
        "Memory {} minutes ago: {:.1} GB used, swap {:.1} GB. Now: {:.1} GB used, swap {:.1} GB. Peak {:.1} GB, {} minutes ago.",
        minutes(since),
        gb(changes.get("used_then")),
        gb(changes.get("swap_then")),
        gb(changes.get("used_now")),
        gb(changes.get("swap_now")),
        gb(changes.get("peak")),
        minutes(changes.get("peak_at").and_then(Value::as_u64).unwrap_or(since)),
    )];
    let apps = changes.get("apps").and_then(Value::as_array).cloned().unwrap_or_default();
    if !apps.is_empty() {
        lines.push("Apps whose memory changed most in that time:".into());
        for app in apps.iter().take(8) {
            let (then, now) = (gb(app.get("then")), gb(app.get("now")));
            let name = app.get("app").and_then(Value::as_str).unwrap_or("?");
            let what = if now == 0.0 { "quit".to_owned() } else if then == 0.0 { "started".to_owned() } else if now < then { "went down".to_owned() } else { "went up".to_owned() };
            lines.push(format!("- {name}: {then:.1} GB -> {now:.1} GB ({what})"));
        }
    }
    Some(lines.join("\n"))
}

fn describe_proc(proc: &Value) -> String {
    let mb = proc.get("memory").and_then(Value::as_u64).unwrap_or(0) as f64 / 1_048_576.0;
    let ports: Vec<String> = proc.get("ports").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_u64).map(|port| format!(":{port}")).collect();
    let mut line = format!(
        "{} (pid {}): CPU {:.0}%, {:.0} MB",
        proc.get("name").and_then(Value::as_str).unwrap_or("?"),
        proc.get("pid").and_then(Value::as_u64).unwrap_or(0),
        proc.get("cpu").and_then(Value::as_f64).unwrap_or(0.0),
        mb
    );
    if !ports.is_empty() {
        line.push_str(&format!(", listening {}", ports.join(" ")));
    }
    line
}

fn mentions(text: &str, words: &[&str]) -> bool {
    let lower = text.to_ascii_lowercase();
    words.iter().any(|word| lower.contains(word))
}

/// A question about the machine itself: its processes, ports and resources are worth reading first.
fn about_machine(text: &str) -> bool {
    mentions(
        text,
        &["process", "port", "cpu", "mem", "ram", "fan", "slow", "disk", "space", "battery", "hot", "running", "pid", "kill", "listen", "swap", "gpu", "load"],
    )
}

//! AI agents on this Mac. A light watcher over the sampler's process snapshot flags an AI command
//! line tool started with its permission-bypass flag by an install script, or with no terminal of
//! the person's above it (the Nx "s1ngularity" technique). The sweep part reads the agent configs
//! statically (never starting a server): plaintext tokens, unpinned `npx -y` servers, servers run
//! from /tmp or Downloads, remote servers, permission-bypass defaults; it remembers each MCP
//! server's definition and alerts when one changes; it looks for hidden text in agent instruction
//! files; and it puts the shell blocks of agent skills through the paste guard (`terminal.scan`).
//! Tokens are counted, never shown.
//!
//! What it remembers is in the graph: `(:AgentConfig {key: path, tool})-[:DEFINES]->(:McpServer
//! {key: file#name, name, command, args, url, hash*})`, the configs `-[:ON]->(:Machine)`, and the
//! skills read as `(:Skill {key: path})-[:IN]->(:Folder)`.

use crate::alerts::Candidate;
use crate::procs::{Entry, Snapshot};
use crate::sweep::Part;
use crate::graph::{self, Props, r};
use crate::util::{home, plural, run, shorten, tilde};
use cc_protocol::Ctx;
use cc_protocol::contracts::system::Alert;
use cc_protocol::contracts::terminal::{PlaceList, ScanResult, methods as terminal_methods};
use regex::Regex;

use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

// Each source names one kind of finding; the terminal flow looks its explanation notes up by it.
const SOURCE_SETTINGS: &str = "agent settings";
const SOURCE_VERSIONS: &str = "MCP versions";
const SOURCE_PROGRAMS: &str = "MCP programs";
const SOURCE_REMOTE: &str = "remote MCP servers";
const SOURCE_SECRETS: &str = "MCP secrets";
const SOURCE_PINS: &str = "MCP definitions";
const SOURCE_HIDDEN: &str = "agent instructions";
const SOURCE_SKILLS: &str = "agent skills";

/// The frame connection, for `terminal.scan` and `terminal.places` (set once the plugin connects).
static CTX: OnceLock<Ctx> = OnceLock::new();
/// Alerts the sweep raised, fired by the watcher's next tick.
static PENDING: Mutex<Vec<Candidate>> = Mutex::new(Vec::new());

pub fn connect(ctx: &Ctx) {
    let _ = CTX.set(ctx.clone());
}

fn pending() -> std::sync::MutexGuard<'static, Vec<Candidate>> {
    PENDING.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

// ---------------------------------------------------------------------------------------------
// 69. The watcher.

/// The AI tools and the flags that turn their permission prompts off. Pairs are a flag and its value.
const TOOLS: &[(&str, &[&str], &[(&str, &str)])] = &[
    ("claude", &["--dangerously-skip-permissions"], &[("--permission-mode", "bypasspermissions")]),
    ("gemini", &["--yolo", "-y"], &[("--approval-mode", "yolo")]),
    ("q", &["--trust-all-tools"], &[]),
    ("codex", &["--dangerously-bypass-approvals-and-sandbox", "--yolo"], &[("--sandbox", "danger-full-access"), ("-s", "danger-full-access")]),
    ("cursor-agent", &["--force", "-f", "--yolo"], &[]),
    ("opencode", &["--dangerously-skip-permissions"], &[]),
    ("aider", &["--yes-always", "--yes"], &[]),
];

/// Interpreters an AI tool's script runs under (its script is then the second word).
const RUNTIMES: &[&str] = &["node", "bun", "deno", "python", "python3"];
const SHELLS: &[&str] = &["zsh", "bash", "sh", "fish", "dash", "tcsh", "ksh", "nu", "pwsh"];
/// Programs that mean a person is at the keyboard: terminals, multiplexers, remote logins, editors.
const PERSON_APPS: &[&str] = &[
    "terminal", "iterm2", "login", "sshd", "sshd-session", "tmux", "screen", "zellij", "ghostty", "wezterm-gui", "alacritty", "kitty",
    "warp", "stable", "hyper", "tabby", "rio", "cc-terminal", "cortexterm", "code helper", "cursor helper", "windsurf helper", "zed",
];
const INSTALLERS: &[&str] = &["npm", "npm-cli.js", "pnpm", "pnpm.cjs", "yarn", "yarn.js", "bun", "pip", "pip3", "uv", "poetry", "pipx"];
const INSTALL_VERBS: &[&str] = &["install", "i", "ci", "add", "update", "upgrade", "rebuild", "sync"];

fn base(word: &str) -> String {
    let name = word.rsplit('/').next().unwrap_or(word).trim_start_matches('-').to_ascii_lowercase();
    for ext in [".js", ".mjs", ".cjs", ".py"] {
        if let Some(stem) = name.strip_suffix(ext) {
            return stem.to_owned();
        }
    }
    name
}

/// Which AI tool a command line starts, from its program (or the script its interpreter runs).
fn tool_of(command: &str) -> Option<&'static str> {
    let words: Vec<&str> = command.split_whitespace().collect();
    let first = base(words.first()?);
    let program = if RUNTIMES.iter().any(|r| first == *r || first.starts_with("python3.")) {
        let script = words.iter().skip(1).find(|w| !w.starts_with('-'))?;
        let packaged = [("@anthropic-ai/claude-code", "claude"), ("@google/gemini-cli", "gemini"), ("@openai/codex", "codex"), ("opencode-ai", "opencode"), ("aider", "aider")];
        if let Some((_, name)) = packaged.iter().find(|(path, _)| script.contains(path)) {
            return TOOLS.iter().find(|t| t.0 == *name).map(|t| t.0);
        }
        base(script)
    } else {
        first
    };
    let program = match program.as_str() {
        "qchat" => "q".to_owned(),
        name if name.starts_with("codex") => "codex".to_owned(),
        name => name.to_owned(),
    };
    TOOLS.iter().find(|t| t.0 == program).map(|t| t.0)
}

/// The bypass flag on a tool's command line, when there is one.
fn bypass_flag(tool: &str, command: &str) -> Option<String> {
    let (_, flags, pairs) = TOOLS.iter().find(|t| t.0 == tool)?;
    let words: Vec<String> = command.split_whitespace().flat_map(|w| w.splitn(2, '=').map(str::to_owned).collect::<Vec<_>>()).collect();
    for (i, word) in words.iter().enumerate() {
        if flags.contains(&word.as_str()) {
            return Some(word.clone());
        }
        if let Some((flag, value)) = pairs.iter().find(|(flag, _)| word == flag)
            && words.get(i + 1).is_some_and(|next| next.to_ascii_lowercase() == *value)
        {
            return Some(format!("{flag} {}", words[i + 1]));
        }
    }
    None
}

/// The whole command line when the snapshot's is cut short.
fn full_command(pid: u32, shown: &str) -> String {
    if !shown.ends_with('…') {
        return shown.to_owned();
    }
    match run("ps", &["-ww", "-o", "args=", "-p", &pid.to_string()], Duration::from_secs(3)) {
        Ok(out) if out.ok && !out.stdout.trim().is_empty() => out.stdout.trim().to_owned(),
        _ => shown.to_owned(),
    }
}

/// `npm install` when this command line is a package install, else `None`.
fn install_of(command: &str) -> Option<String> {
    let words: Vec<&str> = command.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        let name = base(word);
        if !INSTALLERS.contains(&name.as_str()) {
            continue;
        }
        let verb = words[i + 1..].iter().find(|w| !w.starts_with('-')).map(|w| w.to_ascii_lowercase());
        if let Some(verb) = verb.filter(|v| INSTALL_VERBS.contains(&v.as_str()) || (v == "pip" && name == "uv")) {
            let manager = name.trim_end_matches("-cli").trim_end_matches(".cjs");
            return Some(format!("{manager} {verb}"));
        }
    }
    command.contains("postinstall").then(|| "a postinstall script".to_owned())
}

/// A shell a person types into (no `-c`), or a terminal, editor or remote login.
fn is_person(entry: &Entry) -> bool {
    let name = entry.proc.name.trim_start_matches('-').to_ascii_lowercase();
    if PERSON_APPS.iter().any(|app| name == *app || name.starts_with(app)) {
        return true;
    }
    if SHELLS.contains(&name.as_str()) {
        return !entry.proc.command.split_whitespace().skip(1).any(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('c'));
    }
    false
}

/// New AI tool processes with a bypass flag and no person behind them; and the sweep's pending
/// alerts. `seen` holds (pid, start) of processes already looked at.
pub fn watch(snapshot: &Snapshot, seen: &mut HashSet<(u32, u64)>) -> Vec<Candidate> {
    let mut found: Vec<Candidate> = std::mem::take(&mut *pending());
    if snapshot.entries.is_empty() {
        return found;
    }
    let alive: HashSet<(u32, u64)> = snapshot.entries.iter().map(|e| (e.proc.pid, e.proc.started)).collect();
    seen.retain(|key| alive.contains(key));
    let by_pid: HashMap<u32, &Entry> = snapshot.entries.iter().map(|e| (e.proc.pid, e)).collect();
    for entry in &snapshot.entries {
        let p = &entry.proc;
        if !seen.insert((p.pid, p.started)) {
            continue;
        }
        let Some(tool) = tool_of(&p.command) else { continue };
        let command = full_command(p.pid, &p.command);
        let Some(flag) = bypass_flag(tool, &command) else { continue };
        let mut chain = Vec::new();
        let mut parent = p.ppid;
        while parent > 1 && chain.len() < 20 {
            let Some(up) = by_pid.get(&parent) else { break };
            chain.push(*up);
            parent = up.proc.ppid;
        }
        let installer = chain.iter().find_map(|e| install_of(&e.proc.command));
        let person = chain.iter().any(|e| is_person(e));
        let (severity, text) = match (&installer, person) {
            (Some(installer), _) => (
                "high",
                format!(
                    "{tool} (pid {}) started with {flag}, launched by {installer}, not by you. A malicious package used AI tools exactly this way (the s1ngularity attack, 2025) to search the disk for secrets.",
                    p.pid
                ),
            ),
            (None, false) => {
                let by = chain.first().map(|e| e.proc.name.clone()).unwrap_or_else(|| "an unknown program".into());
                ("warn", format!("{tool} (pid {}) started with {flag} by {by}, with no terminal of yours above it. Check that you set this up.", p.pid))
            }
            (None, true) => continue,
        };
        found.push(Candidate {
            key: format!("agent:{}:{}", p.pid, p.started),
            alert: Alert { kind: "agent".into(), severity: severity.into(), text, pid: Some(p.pid), actions: vec!["kill".into(), "show".into()], ..Default::default() },
        });
    }
    found
}

// ---------------------------------------------------------------------------------------------
// The sweep part.

/// Every agent check over the filesystem discovery. Runs blocking (it may wait on the frame for
/// `terminal.scan`), so the sweep calls it through `spawn_blocking`.
pub fn checks(discovery: crate::filesystem::Shared) -> Part {
    let mut part = Part::default();
    let found = discovery.get();
    if discovery.is_cancelled() {
        part.skipped.push("filesystem checks: cancelled before completion".into());
        return part;
    }
    let discovery = found;
    discovery.report(&mut part);
    let repos = known_repos(&mut part, discovery);
    let servers = config_checks(&mut part, &repos, discovery);
    pin_checks(&mut part, &servers);
    hidden_text_checks(&mut part, &repos, discovery);
    skill_checks(&mut part, discovery);
    part
}

/// One read of another plugin, from this blocking thread.
fn ask(method: &str, params: Value, limit: Duration) -> Result<Value, String> {
    let ctx = CTX.get().ok_or("not connected to the frame")?.clone();
    let handle = tokio::runtime::Handle::try_current().map_err(|_| "no async runtime".to_owned())?;
    match handle.block_on(tokio::time::timeout(limit, ctx.call(method, params))) {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(error.to_string()),
        Err(_) => Err(format!("no answer in {} s", limit.as_secs())),
    }
}

/// Remembered places supplement filesystem discovery; they never restrict it.
fn known_repos(part: &mut Part, discovery: &crate::filesystem::Discovery) -> Vec<PathBuf> {
    let mut repos: Vec<PathBuf> = discovery.projects.iter().cloned().collect();
    match ask(terminal_methods::PLACES, json!({"limit": 300}), Duration::from_secs(10))
        .and_then(|v| serde_json::from_value::<PlaceList>(v).map_err(|e| e.to_string()))
    {
        Ok(list) => repos.extend(list.places.into_iter().map(|p| PathBuf::from(p.path)).filter(|p| p.is_dir())),
        Err(error) => part.skipped.push(format!("CortexTerm's places: {error}; filesystem discovery still included")),
    }
    let mut repos: Vec<PathBuf> = repos.into_iter().filter_map(|r| r.canonicalize().ok()).collect();
    repos.sort();
    repos.dedup();
    repos.sort_by_key(|path| !path.starts_with(home()));
    repos
}

// --- 70. Agent and MCP configs.

/// One MCP server as a config defines it.
struct Server {
    /// `~/.cursor/mcp.json#github`: what it is remembered by.
    id: String,
    file: String,
    name: String,
    entry: Value,
}

fn read_text(path: &Path, part: &mut Part) -> Option<String> {
    let meta = match std::fs::metadata(path) {
        Ok(meta) => meta,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                part.skipped.push(format!("agent file {}: {error}", tilde(path)));
            }
            return None;
        }
    };
    if !meta.is_file() { return None; }
    if meta.len() > 8 * 1024 * 1024 {
        part.skipped.push(format!("agent file {}: larger than 8 MiB", tilde(path)));
        return None;
    }
    match std::fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            part.skipped.push(format!("agent file {}: {error}", tilde(path)));
            None
        }
    }
}

/// JSON with comments and trailing commas (VS Code's settings) made plain.
fn parse_jsonc(text: &str) -> Option<Value> {
    if let Ok(value) = serde_json::from_str(text) {
        return Some(value);
    }
    let mut out = String::with_capacity(text.len());
    let chars: Vec<char> = text.chars().collect();
    let (mut i, mut in_string) = (0, false);
    while i < chars.len() {
        let c = chars[i];
        if in_string {
            out.push(c);
            if c == '\\' && i + 1 < chars.len() {
                out.push(chars[i + 1]);
                i += 1;
            } else if c == '"' {
                in_string = false;
            }
        } else if c == '"' {
            in_string = true;
            out.push(c);
        } else if c == '/' && chars.get(i + 1) == Some(&'/') {
            while i < chars.len() && chars[i] != '\n' {
                i += 1;
            }
            continue;
        } else if c == '/' && chars.get(i + 1) == Some(&'*') {
            i += 2;
            while i + 1 < chars.len() && !(chars[i] == '*' && chars[i + 1] == '/') {
                i += 1;
            }
            i += 2;
            continue;
        } else if c == ',' && chars[i + 1..].iter().find(|c| !c.is_whitespace()).is_some_and(|n| *n == '}' || *n == ']') {
            // A trailing comma.
        } else {
            out.push(c);
        }
        i += 1;
    }
    serde_json::from_str(&out).ok()
}

/// The `mcp_servers` tables and the approval settings of Codex's config.toml (a small reader:
/// strings, string arrays and inline tables of strings are all it holds).
fn parse_codex(text: &str) -> Value {
    let quoted = Regex::new(r#""((?:[^"\\]|\\.)*)"|'([^']*)'"#).expect("regex");
    let strings = |s: &str| -> Vec<String> { quoted.captures_iter(s).map(|c| c.get(1).or(c.get(2)).map(|m| m.as_str().to_owned()).unwrap_or_default()).collect() };
    let mut root = json!({"mcp_servers": {}});
    let mut section: Vec<String> = Vec::new();
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && !line.starts_with("[[") {
            let inner = line.trim_matches(|c| c == '[' || c == ']');
            section = inner.split('.').map(|part| part.trim().trim_matches('"').to_owned()).collect();
            continue;
        }
        let Some((key, value)) = line.split_once('=') else { continue };
        let key = key.trim().trim_matches('"').to_owned();
        let mut value = value.trim().to_owned();
        while value.starts_with('[') && value.matches('[').count() > value.matches(']').count() {
            let Some(more) = lines.next() else { break };
            value.push(' ');
            value.push_str(more.trim());
        }
        let parsed = if value.starts_with('[') {
            json!(strings(&value))
        } else if value.starts_with('{') {
            let pairs = Regex::new(r#"("?[\w.-]+"?)\s*=\s*("(?:[^"\\]|\\.)*"|'[^']*')"#).expect("regex");
            let map: serde_json::Map<String, Value> = pairs
                .captures_iter(&value)
                .map(|c| (c[1].trim_matches('"').to_owned(), json!(strings(&c[2]).into_iter().next().unwrap_or_default())))
                .collect();
            Value::Object(map)
        } else if let Some(s) = strings(&value).into_iter().next() {
            json!(s)
        } else {
            json!(value)
        };
        match section.as_slice() {
            [] => root[&key] = parsed,
            [top, name] if top == "mcp_servers" => {
                root["mcp_servers"][name][&key] = parsed;
            }
            [top, name, sub] if top == "mcp_servers" => {
                root["mcp_servers"][name][sub][&key] = parsed;
            }
            [top, name] if top == "profiles" => {
                root["profiles"][name][&key] = parsed;
            }
            _ => {}
        }
    }
    root
}

fn servers_in(map: Option<&Value>, file: &str, out: &mut Vec<Server>) {
    for (name, entry) in map.and_then(Value::as_object).into_iter().flatten() {
        if entry.is_object() {
            out.push(Server { id: format!("{file}#{name}"), file: file.to_owned(), name: name.clone(), entry: entry.clone() });
        }
    }
}

fn secret_re() -> &'static Regex {
    static RE: OnceLock<Regex> = OnceLock::new();
    RE.get_or_init(|| {
        Regex::new(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,}|sk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|(?:AKIA|ASIA)[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|glpat-[A-Za-z0-9_-]{20}|npm_[A-Za-z0-9]{36})")
            .expect("regex")
    })
}

/// A literal secret value (not a `${VAR}` or `env:` reference).
fn is_secret(key: &str, value: &str) -> bool {
    let value = value.trim();
    if value.is_empty() || value.contains("${") || value.starts_with('$') || value.starts_with("{{") || value.starts_with("env:") || value.starts_with("op://") {
        return false;
    }
    if secret_re().is_match(value) {
        return true;
    }
    // The key's words (`GITHUB_PERSONAL_ACCESS_TOKEN`, `apiKey`, `--api-key`).
    let mut spaced = String::new();
    for (i, c) in key.chars().enumerate() {
        if c.is_ascii_uppercase() && i > 0 && key[..i].chars().last().is_some_and(|p| p.is_ascii_lowercase()) {
            spaced.push(' ');
        }
        spaced.push(if c.is_ascii_alphanumeric() { c.to_ascii_lowercase() } else { ' ' });
    }
    let words = ["token", "secret", "key", "apikey", "password", "passwd", "auth", "authorization", "bearer", "credential", "credentials", "pat"];
    let named = spaced.split_whitespace().any(|w| words.contains(&w));
    let literal = value.strip_prefix("Bearer ").unwrap_or(value);
    let plain = literal.starts_with('/') || literal.starts_with('~') || literal.starts_with('.') || literal.starts_with("http") || literal.parse::<f64>().is_ok();
    named && !plain && literal.len() >= 12 && !literal.contains(' ')
}

/// An argument with any secret in it masked.
fn mask(arg: &str) -> String {
    let masked = secret_re().replace_all(arg, "•••").into_owned();
    match masked.split_once('=') {
        Some((key, value)) if is_secret(key, value) => format!("{key}=•••"),
        _ => masked,
    }
}

fn strings_of(value: &Value) -> Vec<String> {
    value.as_array().into_iter().flatten().filter_map(Value::as_str).map(str::to_owned).collect()
}

/// The package an `npx -y`/`bunx`/`uvx`/`pnpm dlx` server runs, when it is not pinned to a version.
fn unpinned(command: &str, args: &[String]) -> Option<String> {
    let program = base(command);
    let rest: Vec<&String> = match program.as_str() {
        "npx" | "bunx" | "uvx" => args.iter().collect(),
        "pnpm" | "yarn" | "bun" if args.first().is_some_and(|a| a == "dlx" || a == "x") => args.iter().skip(1).collect(),
        "pipx" if args.first().is_some_and(|a| a == "run") => args.iter().skip(1).collect(),
        "uv" if args.first().is_some_and(|a| a == "tool") && args.get(1).is_some_and(|a| a == "run") => args.iter().skip(2).collect(),
        _ => return None,
    };
    // `--from pkg==1.2` (uvx) names the package; else the first word that is not a flag.
    let package = rest.windows(2).find(|w| w[0] == "--from").map(|w| w[1].clone()).or_else(|| {
        let mut skip = false;
        rest.iter()
            .find(|a| {
                if skip {
                    skip = false;
                    return false;
                }
                if matches!(a.as_str(), "-p" | "--package" | "--python" | "--with") {
                    skip = true;
                    return false;
                }
                !a.starts_with('-')
            })
            .map(|a| a.to_string())
    })?;
    let package = package.strip_prefix("--package=").unwrap_or(&package).to_owned();
    let version = match package.strip_prefix('@') {
        Some(scoped) => scoped.split_once('@').map(|(_, v)| v.to_owned()),
        None if package.contains("==") => package.split_once("==").map(|(_, v)| v.to_owned()),
        None => package.split_once('@').map(|(_, v)| v.to_owned()),
    };
    match version.as_deref() {
        None | Some("") | Some("latest") | Some("next") => Some(package),
        Some(v) if v.starts_with('^') || v.starts_with('~') || v.starts_with('>') || v.contains('*') || v.contains('x') => Some(package),
        _ => None,
    }
}

fn risky_place(path: &str) -> Option<&'static str> {
    let home = home().display().to_string();
    let path = path.replacen('~', &home, 1);
    [("/tmp/", "/tmp"), ("/private/tmp/", "/tmp"), ("/var/folders/", "a temporary folder"), ("/Users/Shared/", "/Users/Shared")]
        .iter()
        .find(|(prefix, _)| path.starts_with(prefix))
        .map(|(_, label)| *label)
        .or_else(|| path.starts_with(&format!("{home}/Downloads/")).then_some("Downloads"))
}

/// The settings that turn an agent's permission prompts off, wherever they sit in a settings file.
fn bypass_settings(value: &Value, path: &mut Vec<String>, out: &mut Vec<String>) {
    match value {
        Value::Object(map) => {
            for (key, inner) in map {
                path.push(key.clone());
                let hit = match (key.as_str(), inner) {
                    ("defaultMode", Value::String(s)) => s == "bypassPermissions",
                    ("dangerouslySkipPermissions" | "chat.tools.autoApprove" | "chat.tools.global.autoApprove", Value::Bool(true)) => true,
                    ("approvalMode" | "defaultApprovalMode", Value::String(s)) => s.eq_ignore_ascii_case("yolo"),
                    ("approval_policy", Value::String(s)) => s == "never",
                    ("sandbox_mode", Value::String(s)) => s == "danger-full-access",
                    _ => false,
                };
                if hit {
                    out.push(format!("{} = {}", path.join("."), inner));
                }
                // A project's own settings inside ~/.claude.json are skipped: they hold history too.
                if !(key == "projects" && path.len() == 1) {
                    bypass_settings(inner, path, out);
                }
                path.pop();
            }
        }
        _ => {}
    }
}

/// Read every agent config; findings for what is risky in them; the MCP servers they define.
fn config_checks(part: &mut Part, repos: &[PathBuf], discovery: &crate::filesystem::Discovery) -> Vec<Server> {
    let h = home();
    let app_support = h.join("Library/Application Support");
    let files: Vec<PathBuf> = vec![
        h.join(".claude.json"),
        h.join(".claude/settings.json"),
        h.join(".claude/settings.local.json"),
        app_support.join("Claude/claude_desktop_config.json"),
        h.join(".cursor/mcp.json"),
        h.join(".codeium/windsurf/mcp_config.json"),
        app_support.join("Code/User/mcp.json"),
        app_support.join("Code/User/settings.json"),
        app_support.join("Cursor/User/settings.json"),
        h.join(".gemini/settings.json"),
        h.join(".codex/config.toml"),
    ];
    let mut project_files = Vec::new();
    for repo in repos {
        for name in [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json", ".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json"] {
            project_files.push(repo.join(name));
        }
    }
    let mut all: Vec<PathBuf> = files.into_iter().chain(project_files).chain(discovery.agent_configs.iter().cloned()).collect();
    all.sort();
    all.dedup();
    all.sort_by_key(|path| !path.starts_with(home()));
    let mut servers = Vec::new();
    let mut read = 0;
    for path in &all {
        let Some(text) = read_text(path, part) else { continue };
        let shown = tilde(path);
        let value = if path.extension().is_some_and(|e| e == "toml") { Some(parse_codex(&text)) } else { parse_jsonc(&text) };
        let Some(value) = value else {
            part.skipped.push(format!("{shown}: not readable as JSON"));
            continue;
        };
        read += 1;
        servers_in(value.get("mcpServers"), &shown, &mut servers);
        servers_in(value.get("servers"), &shown, &mut servers);
        servers_in(value.get("mcp_servers"), &shown, &mut servers);
        servers_in(value.get("mcp").and_then(|m| m.get("servers")), &shown, &mut servers);
        for (project, settings) in value.get("projects").and_then(Value::as_object).into_iter().flatten() {
            servers_in(settings.get("mcpServers"), &format!("{shown} ({})", tilde(Path::new(project))), &mut servers);
        }
        let mut bypass = Vec::new();
        bypass_settings(&value, &mut Vec::new(), &mut bypass);
        if !bypass.is_empty() {
            part.add(
                "medium",
                "agent",
                format!("{shown} turns an AI agent's permission prompts off ({}): it runs commands and edits files without asking.", bypass.join(", ")),
                None,
                SOURCE_SETTINGS,
            );
        }
    }
    if read == 0 {
        part.skipped.push("agent configs: no Claude, Cursor, Windsurf, VS Code, Codex or Gemini config found".into());
        return servers;
    }
    part.checked.push(format!("agent configs ({})", plural(read, "file", "files")));

    let mut secrets: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
    for server in &servers {
        let e = &server.entry;
        let command = e.get("command").and_then(Value::as_str).unwrap_or("");
        let args = strings_of(e.get("args").unwrap_or(&Value::Null));
        let mut count = 0;
        for field in ["env", "headers", "http_headers"] {
            for (key, value) in e.get(field).and_then(Value::as_object).into_iter().flatten() {
                if value.as_str().is_some_and(|v| is_secret(key, v)) {
                    count += 1;
                }
            }
        }
        for (i, arg) in args.iter().enumerate() {
            let flagged = match arg.split_once('=') {
                Some((key, value)) => is_secret(key, value),
                None => secret_re().is_match(arg) || (i > 0 && args[i - 1].starts_with("--") && is_secret(&args[i - 1], arg)),
            };
            count += usize::from(flagged);
        }
        if count > 0 {
            let slot = secrets.entry(server.file.clone()).or_default();
            slot.0 += count;
            slot.1.push(server.name.clone());
        }
        if let Some(package) = unpinned(command, &args) {
            part.add(
                "medium",
                "agent",
                format!(
                    "The MCP server “{}” in {} runs {} {} without a fixed version, so every start may fetch new code from the registry. Pin a version (for example {}{}1.2.3).",
                    server.name,
                    server.file,
                    base(command),
                    package,
                    package.trim_end_matches("@latest"),
                    if matches!(base(command).as_str(), "uvx" | "uv" | "pipx") { "==" } else { "@" }
                ),
                None,
                SOURCE_VERSIONS,
            );
            part.about("McpServer", server.id.clone());
        }
        let program = if RUNTIMES.contains(&base(command).as_str()) { args.first().map(String::as_str).unwrap_or(command) } else { command };
        if let Some(place) = risky_place(program) {
            part.add(
                "high",
                "agent",
                format!("The MCP server “{}” in {} runs a program from {place} ({}), a folder anything can write to.", server.name, server.file, mask(program)),
                None,
                SOURCE_PROGRAMS,
            );
            part.about("McpServer", server.id.clone());
        }
        let url = ["url", "serverUrl", "httpUrl"].iter().find_map(|k| e.get(*k).and_then(Value::as_str)).map(str::to_owned).or_else(|| {
            (base(command) == "npx" || base(command) == "mcp-remote").then(|| args.iter().find(|a| a.starts_with("http")).cloned()).flatten()
        });
        if let Some(url) = url {
            let host = url.split("://").nth(1).unwrap_or(&url).split('/').next().unwrap_or("").to_owned();
            let local = host.starts_with("localhost") || host.starts_with("127.") || host.starts_with("[::1]");
            if url.starts_with("http://") && !local {
                part.add("low", "agent", format!("The MCP server “{}” in {} talks to {host} over plain http: what it sends and gets can be read on the network.", server.name, server.file), None, SOURCE_REMOTE);
                part.about("McpServer", server.id.clone());
            } else if !local {
                part.add("info", "agent", format!("The MCP server “{}” in {} is a remote server at {host}: what an agent sends it leaves this Mac.", server.name, server.file), None, SOURCE_REMOTE);
                part.about("McpServer", server.id.clone());
            }
        }
    }
    for (file, (count, names)) in secrets {
        part.add(
            "medium",
            "agent",
            format!(
                "{file} holds {} in plain text in its MCP server settings ({}). Any program that can read the file can use {}; keep {} in environment variables or the Keychain instead.",
                plural(count, "secret", "secrets"),
                names.join(", "),
                if count == 1 { "it" } else { "them" },
                if count == 1 { "it" } else { "them" }
            ),
            None,
            SOURCE_SECRETS,
        );
        part.about("AgentConfig", config_of(&file));
    }
    servers
}

// --- 71. Changed MCP definitions.

#[derive(Default)]
struct Pins {
    servers: BTreeMap<String, Pin>,
}

static PINS: Mutex<Option<Pins>> = Mutex::new(None);

/// The MCP definitions remembered, from the graph (at start).
pub async fn load() -> Result<usize, String> {
    let rows = graph::query_all("MATCH (:AgentConfig)-[:DEFINES]->(m:McpServer) RETURN m.key, m.hash, m.command, m.args, m.url ORDER BY m.key", json!({})).await?;
    let mut pins = Pins::default();
    for row in rows {
        pins.servers.insert(graph::text(&row[0]), Pin { hash: graph::text(&row[1]), command: graph::text(&row[2]), args: graph::texts(&row[3]), url: graph::text(&row[4]) });
    }
    let count = pins.servers.len();
    *PINS.lock().unwrap_or_else(|p| p.into_inner()) = Some(pins);
    Ok(count)
}

/// The config file a server is defined in (its id's file part, without a project note).
fn config_path(server: &Server) -> String {
    config_of(&server.file)
}

/// A config file as shown (`~/.claude.json (~/DEV/x)`) as its path.
fn config_of(file: &str) -> String {
    let shown = file.split(" (").next().unwrap_or(file);
    match shown.strip_prefix("~/") {
        Some(rest) => home().join(rest).display().to_string(),
        None => shown.to_owned(),
    }
}

/// Which AI tool a config belongs to, from its path.
fn agent_tool_of(path: &str) -> &'static str {
    let lower = path.to_lowercase();
    [(".claude", "claude"), (".cursor", "cursor"), (".codex", "codex"), ("windsurf", "windsurf"), (".codeium", "windsurf"), (".gemini", "gemini"), ("code/user", "vscode"), ("zed", "zed")]
        .iter()
        .find(|(needle, _)| lower.contains(needle))
        .map(|(_, tool)| *tool)
        .unwrap_or("agent")
}

/// A server and its config, as graph units.
fn server_unit(server: &Server, pin: &Pin, machine: &cc_protocol::contracts::memory::GraphRef) -> graph::Unit {
    let mut unit = graph::Unit::default();
    let config = config_path(server);
    unit.node("AgentConfig", config.clone()).p("tool", agent_tool_of(&config));
    unit.edge(r("AgentConfig", config.clone()), "ON", machine.clone());
    unit.node("McpServer", server.id.clone()).p("name", server.name.clone()).p("command", pin.command.clone()).pl("args", pin.args.clone()).p("url", pin.url.clone()).t("hash", pin.hash.clone());
    unit.edge(r("AgentConfig", config), "DEFINES", r("McpServer", server.id.clone()));
    unit
}

#[derive(Clone, Default, PartialEq)]
struct Pin {
    hash: String,
    command: String,
    args: Vec<String>,
    url: String,
}

/// What a server's definition is remembered by: command, arguments, address and the names of its
/// environment and headers (never their values).
fn pin_of(entry: &Value) -> Pin {
    let command = entry.get("command").and_then(Value::as_str).unwrap_or("").to_owned();
    let args: Vec<String> = strings_of(entry.get("args").unwrap_or(&Value::Null)).iter().map(|a| mask(a)).collect();
    let url = ["url", "serverUrl", "httpUrl"].iter().find_map(|k| entry.get(*k).and_then(Value::as_str)).unwrap_or("").to_owned();
    let keys = |field: &str| -> Vec<String> { entry.get(field).and_then(Value::as_object).map(|m| m.keys().cloned().collect()).unwrap_or_default() };
    let canonical = json!({"command": command, "args": args, "url": url, "type": entry.get("type"), "env": keys("env"), "headers": keys("headers"), "cwd": entry.get("cwd")}).to_string();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in canonical.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    Pin { hash: format!("{hash:016x}"), command, args, url }
}

fn pin_checks(part: &mut Part, servers: &[Server]) {
    if servers.is_empty() {
        return;
    }
    let mut slot = PINS.lock().unwrap_or_else(|p| p.into_inner());
    let machine = graph::machine();
    let keeps = slot.is_some() && machine.is_some();
    let mut scratch = Pins::default();
    let pins = match slot.as_mut() {
        Some(pins) => pins,
        None => &mut scratch,
    };
    let first = pins.servers.is_empty();
    for server in servers {
        let now = pin_of(&server.entry);
        if let Some(machine) = machine.as_ref().filter(|_| keeps) {
            part.graph.units.push(server_unit(server, &now, machine));
        }
        let before = pins.servers.insert(server.id.clone(), now.clone());
        let Some(before) = before.filter(|b| b.hash != now.hash) else { continue };
        let mut what = Vec::new();
        if before.command != now.command {
            what.push(format!("command {} → {}", before.command, now.command));
        }
        if before.args != now.args {
            what.push(format!("arguments “{}” → “{}”", shorten(&before.args.join(" "), 80), shorten(&now.args.join(" "), 80)));
        }
        if before.url != now.url {
            what.push(format!("address {} → {}", before.url, now.url));
        }
        if what.is_empty() {
            what.push("its settings".into());
        }
        let text = format!("The MCP server “{}” in {} changed since the last check: {}. If you did not change it, an update or another program did.", server.name, server.file, what.join("; "));
        part.add("medium", "agent", text.clone(), None, SOURCE_PINS);
        part.about("McpServer", server.id.clone());
        pending().push(Candidate {
            key: format!("agent-mcp:{}:{}", server.id, now.hash),
            alert: Alert { kind: "agent".into(), severity: "warn".into(), text, actions: vec!["show".into()], ..Default::default() },
        });
    }
    drop(slot);
    part.checked.push(if first && !keeps {
        "MCP definitions (no record yet: memory is not reachable, so nothing was compared)".into()
    } else if first { "MCP definitions (first look: remembered for next time)".into() } else { format!("MCP definitions ({})", plural(servers.len(), "server", "servers")) });
}

// --- 72. Hidden text in instruction files.

const INSTRUCTION_FILES: &[&str] =
    &["CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".windsurfrules", ".github/copilot-instructions.md"];

fn instruction_files(repos: &[PathBuf]) -> Vec<PathBuf> {
    let h = home();
    let mut files =
        vec![h.join(".claude/CLAUDE.md"), h.join(".codex/AGENTS.md"), h.join(".gemini/GEMINI.md"), h.join(".codeium/windsurf/memories/global_rules.md")];
    let mut rule_dirs = vec![h.join(".cursor/rules")];
    for repo in repos {
        files.extend(INSTRUCTION_FILES.iter().map(|name| repo.join(name)));
        rule_dirs.push(repo.join(".cursor/rules"));
    }
    for dir in rule_dirs {
        for entry in std::fs::read_dir(&dir).into_iter().flatten().flatten() {
            if entry.path().extension().is_some_and(|e| e == "mdc" || e == "md") {
                files.push(entry.path());
            }
        }
    }
    files.into_iter().filter(|f| f.is_file()).collect()
}

/// The hidden characters in a text, by kind, and what its Unicode tag characters spell.
#[derive(Default)]
struct Hidden {
    zero_width: usize,
    bidi: usize,
    tags: usize,
    escapes: usize,
    spelled: String,
}

fn hidden_in(text: &str) -> Hidden {
    let mut found = Hidden::default();
    for (i, c) in text.chars().enumerate() {
        match c as u32 {
            0xFEFF if i == 0 => {}
            0x200B..=0x200D | 0x2060 | 0xFEFF | 0x180E => found.zero_width += 1,
            0x202A..=0x202E | 0x2066..=0x2069 => found.bidi += 1,
            0xE0000..=0xE007F => {
                found.tags += 1;
                let ascii = (c as u32 - 0xE0000) as u8;
                if (0x20..0x7F).contains(&ascii) {
                    found.spelled.push(ascii as char);
                }
            }
            0x1B => found.escapes += 1,
            _ => {}
        }
    }
    found
}

fn hidden_text_checks(part: &mut Part, repos: &[PathBuf], discovery: &crate::filesystem::Discovery) {
    let mut files = instruction_files(repos);
    files.extend(discovery.instructions.iter().cloned());
    files.sort();
    files.dedup();
    files.sort_by_key(|path| !path.starts_with(home()));
    if files.is_empty() {
        part.skipped.push("hidden text in agent instructions: no CLAUDE.md, AGENTS.md, GEMINI.md or rules files found".into());
        return;
    }
    part.checked.push(format!("hidden text in agent instructions ({})", plural(files.len(), "file", "files")));
    for path in files {
        let Some(text) = read_text(&path, part) else { continue };
        let h = hidden_in(&text);
        let mut what = Vec::new();
        if h.tags > 0 {
            what.push(plural(h.tags, "invisible tag character", "invisible tag characters"));
        }
        if h.zero_width > 0 {
            what.push(plural(h.zero_width, "zero-width character", "zero-width characters"));
        }
        if h.bidi > 0 {
            what.push(plural(h.bidi, "text-direction control", "text-direction controls"));
        }
        if h.escapes > 0 {
            what.push(plural(h.escapes, "terminal escape code", "terminal escape codes"));
        }
        if what.is_empty() {
            continue;
        }
        let shown = tilde(&path);
        let spelled = h.spelled.trim();
        let decoded = if spelled.is_empty() { String::new() } else { format!(" The hidden characters spell: “{}”.", shorten(spelled, 120)) };
        part.add(
            "high",
            "agent",
            format!("{shown}, which AI agents read as instructions, holds text people cannot see ({}).{decoded}", what.join(", ")),
            Some(format!(
                "perl -CSD -i -pe 's/[\\x{{200B}}-\\x{{200D}}\\x{{2060}}\\x{{180E}}\\x{{202A}}-\\x{{202E}}\\x{{2066}}-\\x{{2069}}\\x{{E0000}}-\\x{{E007F}}\\x{{1B}}]//g' {}",
                shell_quote(&shown)
            )),
            SOURCE_HIDDEN,
        );
    }
}

fn shell_quote(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) if rest.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c)) => path.to_owned(),
        _ if path.chars().all(|c| c.is_ascii_alphanumeric() || "/._-".contains(c)) => path.to_owned(),
        Some(rest) => format!("~/'{}'", rest.replace('\'', "'\\''")),
        None => format!("'{}'", path.replace('\'', "'\\''")),
    }
}

// --- 73. Skills through the paste guard.

/// The shell a skill tells its reader to run: its shell code blocks, and lines that pipe a
/// download into a shell anywhere in the text.
fn shell_of(text: &str) -> String {
    let mut out = Vec::new();
    let mut lines = text.lines();
    let piped = Regex::new(r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b").expect("regex");
    while let Some(line) = lines.next() {
        let fence = line.trim_start();
        if let Some(lang) = fence.strip_prefix("```") {
            let lang = lang.trim().to_ascii_lowercase();
            let shell = matches!(lang.as_str(), "sh" | "bash" | "zsh" | "shell" | "console" | "terminal" | "fish");
            for inner in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    break;
                }
                if shell {
                    out.push(inner.trim_start().strip_prefix("$ ").unwrap_or(inner).to_owned());
                } else if piped.is_match(inner) {
                    out.push(inner.to_owned());
                }
            }
        } else if piped.is_match(line) {
            out.push(line.trim().trim_matches('`').to_owned());
        }
    }
    out.join("\n")
}

/// The minimal stealer shapes, used only when the paste guard cannot be reached.
fn local_scan(text: &str) -> Vec<(String, String, String)> {
    let rules = [
        ("pipe-to-shell", "medium", r"(?i)\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", "Downloads a script and runs it at once."),
        ("base64-to-shell", "high", r"(?i)base64\s+(-d|-D|--decode)[^\n|]*\|\s*(ba|z|da)?sh\b", "Decodes hidden text and runs it as a command."),
        ("fake-password-prompt", "high", r"(?i)osascript[^\n]*hidden answer", "Shows a fake password dialog."),
        ("quarantine-removal", "high", r"(?i)xattr\s+(-[a-z]*[dc][a-z]*\s+)+(com\.apple\.quarantine|\S)", "Removes the download quarantine, so macOS does not check the program."),
    ];
    rules
        .iter()
        .filter(|(_, _, pattern, _)| Regex::new(pattern).is_ok_and(|re| re.is_match(text)))
        .map(|(rule, severity, _, what)| (rule.to_string(), severity.to_string(), what.to_string()))
        .collect()
}

fn skill_checks(part: &mut Part, discovery: &crate::filesystem::Discovery) {
    let mut files: Vec<PathBuf> = discovery.skills.iter().cloned().collect();
    files.sort_by_key(|path| !path.starts_with(home()));
    if files.is_empty() {
        part.skipped.push("agent skills: no skill files found".into());
        return;
    }
    let mut guard = true;
    let mut scanned = 0;
    let mut steps = Vec::new();
    for path in &files {
        let Some(text) = read_text(path, part) else { continue };
        let shell = shell_of(&text);
        scanned += 1;
        if graph::machine().is_some() {
            let unit = part.graph.unit();
            let folder = graph::folder(unit, path.parent().unwrap_or(Path::new("/")));
            unit.node("Skill", path.display().to_string());
            unit.edge(r("Skill", path.display().to_string()), "IN", folder);
        }
        if shell.trim().is_empty() {
            continue;
        }
        let threats: Vec<(String, String, String)> = if guard {
            match ask(terminal_methods::SCAN, json!({"text": shell}), Duration::from_secs(10)).and_then(|v| serde_json::from_value::<ScanResult>(v).map_err(|e| e.to_string())) {
                Ok(result) => result.threats.into_iter().map(|t| (t.rule, t.severity, t.text)).collect(),
                Err(error) => {
                    part.skipped.push(format!("paste guard for agent skills ({error}): used a short local rule list instead"));
                    guard = false;
                    local_scan(&shell)
                }
            }
        } else {
            local_scan(&shell)
        };
        // A skill is a document: install and build steps (run from a temp folder, curl into a
        // shell) are normal in developer docs. Only what an attack skill does to this Mac alerts.
        let attacks: Vec<_> = threats.iter().filter(|t| ATTACKS.contains(&t.0.as_str())).collect();
        if attacks.is_empty() {
            if !threats.is_empty() {
                steps.push(path);
            }
            continue;
        }
        let rules: Vec<String> = attacks.iter().map(|t| t.0.clone()).collect::<std::collections::BTreeSet<_>>().into_iter().collect();
        let what: Vec<String> = attacks.iter().map(|t| format!("{}.", t.2.trim().trim_end_matches('.'))).collect::<std::collections::BTreeSet<_>>().into_iter().take(3).collect();
        part.add(
            "high",
            "agent",
            format!("The agent skill {} tells its reader to run commands that steal or hand over this Mac ({}): {}", tilde(path), rules.join(", "), what.join(" ")),
            None,
            SOURCE_SKILLS,
        );
        part.about("Skill", path.display().to_string());
    }
    if !steps.is_empty() {
        let names: Vec<String> = steps.iter().take(3).map(|path| tilde(path)).collect();
        let more = if steps.len() > 3 { format!(" and {} more", steps.len() - 3) } else { String::new() };
        part.add(
            "info",
            "agent",
            format!("{} include install or build steps (running from a temporary folder, a download into a shell): {}{more}. Normal in developer docs; nothing in them steals or hands over this Mac.", plural(steps.len(), "agent skill", "agent skills"), names.join(", ")),
            None,
            SOURCE_SKILLS,
        );
    }
    part.checked.push(format!("agent skills through the {} ({})", if guard { "paste guard" } else { "local rules" }, plural(scanned, "file", "files")));
}

/// What an attack skill makes its agent do to this Mac: steal passwords, keychains or secrets,
/// hand over control, run a hidden payload, hide text from the person, or turn protection off.
const ATTACKS: [&str; 16] = [
    "fake-password-prompt", "password-check", "keychain-read", "keychain-dump", "keychain-unlock", "reverse-shell",
    "decode-to-shell", "base64-to-shell", "secrets-sent", "upload-exfil-host", "security-off", "hidden-text",
    "zero-width", "direction-marks", "terminal-codes", "lookalike-domain",
];

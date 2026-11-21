//! Limited cross-statement evidence for CHECK SCRIPT FIRST, not an execution/risk authority.
//! No process, file-content or network access. Stop at unknown control/commands, rather than
//! silently modeling them as no-ops. Paths are lexical, not claims about the actual filesystem.

use crate::shell_text::{self, Token, Word};
use cc_protocol::contracts::terminal::{ScriptAnalysis, ScriptEffect};
use std::collections::{HashMap, HashSet};
use std::time::{Duration, Instant};

const BUDGET: Duration = Duration::from_millis(30);
const MAX_STEPS: u32 = 512;
const MAX_FINDINGS: usize = 16;
const MAX_VARS: usize = 128;
const MAX_PATHS: usize = 128;
const MAX_VALUE: usize = 4096;

#[derive(Clone)]
struct Value {
    exact: Option<String>,
    /// Evaluation with uncertain variables empty, solely for an explicitly conditional witness.
    empty_case: Option<String>,
    causes: Vec<u32>,
    assumptions: Vec<String>,
    /// Command substitutions can change filesystem state, although not the parent's variables.
    external: bool,
}

impl Value {
    fn literal(text: String) -> Self {
        Self { exact: Some(text.clone()), empty_case: Some(text), causes: Vec::new(), assumptions: Vec::new(), external: false }
    }

    fn unknown(line: u32, why: String) -> Self {
        Self { exact: None, empty_case: Some(String::new()), causes: vec![line], assumptions: vec![why], external: false }
    }
}

#[derive(Clone)]
struct FileState { written: u32, read: bool }

struct State {
    vars: HashMap<String, Value>,
    unset: HashSet<String>,
    files: HashMap<String, FileState>,
    dirs: Vec<String>,
    cwd: Option<String>,
    nounset: bool,
    report: ScriptAnalysis,
}

fn variable(name: &str) -> bool {
    !name.is_empty() && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// These have shell behavior beyond an ordinary string binding. Do not shadow that behavior
/// with a guessed value, or keep reasoning after changing expansion/command lookup rules.
fn special(name: &str) -> bool {
    matches!(name, "IFS" | "CDPATH" | "PATH" | "SHELLOPTS" | "BASHOPTS" | "GLOBIGNORE"
        | "RANDOM" | "SRANDOM" | "SECONDS" | "LINENO" | "BASHPID" | "UID" | "EUID"
        | "PPID" | "BASH_SUBSHELL" | "SHLVL" | "ZSH_SUBSHELL" | "status" | "pipestatus")
}

impl State {
    fn limit(&mut self, text: String) {
        if self.report.limits.len() < 8 && !self.report.limits.contains(&text) { self.report.limits.push(text); }
    }

    fn stop(&mut self, line: u32, reason: &str) {
        self.report.stopped_at = Some(line);
        self.report.limits.truncate(7);
        self.report.limits.push(format!("Line {line}: {reason}. Later statements were not analyzed."));
    }

    /// Expand only plain named variables, ${name}, ${name:-literal} and ${name:?message}.
    /// Quote boundaries are retained; escaped/single-quoted dollars remain literal.
    fn value(&self, raw: &str, line: u32) -> Result<Value, &'static str> {
        let mut result = Value::literal(String::new());
        let chars: Vec<char> = raw.chars().collect();
        let mut i = 0;
        let mut quote = None;
        while i < chars.len() {
            let c = chars[i];
            let piece = match (quote, c) {
                (Some('\''), '\'') | (Some('"'), '"') => { quote = None; i += 1; continue; }
                (Some('\''), _) => Value::literal(c.to_string()),
                (_, '\\') => {
                    i += 1;
                    let Some(c) = chars.get(i) else { return Err("unfinished escape"); };
                    if *c == '\n' { i += 1; continue; }
                    let text = if quote == Some('"') && !"$`\"\\".contains(*c) { format!("\\{c}") } else { c.to_string() };
                    Value::literal(text)
                }
                (None, '\'' | '"') => { quote = Some(c); i += 1; continue; }
                (_, '`') | (_, '$') if c == '`' || chars.get(i + 1) == Some(&'(') => {
                    if c == '$' && chars.get(i + 2) == Some(&'(') { return Err("arithmetic expansion is not modeled"); }
                    // Keep the output unknown. Parsing the inner shell is deliberately not a
                    // claim of knowing its exit, output or side effects.
                    let backtick = c == '`';
                    let end = substitution_end(&chars, i, backtick).ok_or("unfinished command substitution")?;
                    i = end;
                    let mut v = Value::unknown(line, format!("The command output assigned at line {line} is empty; that command was not evaluated."));
                    v.external = true;
                    v
                }
                (_, '$') => {
                    let start = i + 1;
                    let (name, modifier, end) = if chars.get(start) == Some(&'{') {
                        let end = chars[start + 1..].iter().position(|c| *c == '}').map(|p| start + 1 + p).ok_or("unfinished variable expansion")?;
                        let inner: String = chars[start + 1..end].iter().collect();
                        let (name, modifier) = if let Some((name, tail)) = inner.split_once(":-") { (name.to_owned(), Some(('-', tail.to_owned()))) }
                            else if let Some((name, tail)) = inner.split_once(":?") { (name.to_owned(), Some(('?', tail.to_owned()))) }
                            else { (inner, None) };
                        (name, modifier, end)
                    } else {
                        let mut end = start;
                        while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') { end += 1; }
                        if end == start { return Err("unsupported shell expansion"); }
                        (chars[start..end].iter().collect(), None, end - 1)
                    };
                    if !variable(&name) { return Err("unsupported variable expansion"); }
                    if special(&name) { return Err("special shell variable behavior is not modeled"); }
                    i = end;
                    let existing = self.vars.get(&name).cloned();
                    let mut v = existing.unwrap_or_else(|| Value::unknown(line, format!("{name} is empty; its environment value is not known.")));
                    if self.nounset && self.unset.contains(&name) && modifier.is_none() { return Err("an unset variable stops this shell before later effects"); }
                    if let Some((kind, fallback)) = modifier {
                        if fallback.contains(['$', '`', '\\', '\'', '"', '{']) { return Err("nonliteral default or required-variable message expansion"); }
                        if kind == '?' {
                            if v.exact.as_deref() == Some("") { return Err("a required variable is empty; later effects are not assumed to execute"); }
                            if v.exact.is_none() { v.empty_case = None; }
                        } else {
                            // Only literal defaults; nested/default side effects remain unknown.
                            if v.exact.as_deref() == Some("") { v = Value::literal(fallback); }
                            else if v.exact.is_none() { v.empty_case = Some(fallback); }
                        }
                    }
                    if v.exact.is_none() && v.empty_case.as_deref() == Some("") && !v.assumptions.iter().any(|s| s.contains(&name)) {
                        v.assumptions.push(format!("{name} is empty at line {line}."));
                    }
                    v
                }
                (None, '~' | '[' | '?' | '*') => return Err("unsupported tilde or filename expansion"),
                _ => Value::literal(c.to_string()),
            };
            result.exact = match (result.exact, piece.exact) { (Some(a), Some(b)) => Some(a + &b), _ => None };
            result.empty_case = match (result.empty_case, piece.empty_case) { (Some(a), Some(b)) => Some(a + &b), _ => None };
            for cause in piece.causes { if !result.causes.contains(&cause) { result.causes.push(cause); } }
            for assumption in piece.assumptions { if !result.assumptions.contains(&assumption) { result.assumptions.push(assumption); } }
            result.external |= piece.external;
            if result.causes.len() > 32 || result.assumptions.len() > 32 { return Err("variable dependency budget reached"); }
            if result.exact.as_ref().or(result.empty_case.as_ref()).is_some_and(|v| v.len() > MAX_VALUE) { return Err("expanded value exceeds the inspection limit"); }
            i += 1;
        }
        if quote.is_some() { return Err("unfinished quote"); }
        Ok(result)
    }

    fn statement(&mut self, words: &[Word<'_>]) -> Result<(), &'static str> {
        if words.is_empty() { return Ok(()); }
        let line = words[0].line;
        let mut at = 0;
        let exporting = words[0].literal().as_deref() == Some("export");
        if exporting { at += 1; }
        let first_assignment = at;
        while let Some(word) = words.get(at) {
            let Some((name, _)) = word.raw.split_once('=') else { break; };
            if !variable(name) { break; }
            at += 1;
        }
        if at == words.len() && at > first_assignment {
            for word in &words[first_assignment..at] {
                let (name, raw) = word.raw.split_once('=').unwrap();
                if special(name) { return Err("assignment changes special shell state outside this check"); }
                let mut value = self.value(raw, word.line)?;
                if self.vars.len() >= MAX_VARS && !self.vars.contains_key(name) { return Err("variable budget reached"); }
                if value.external {
                    self.files.clear(); self.dirs.clear();
                    self.limit(format!("Line {line}: command output and filesystem side effects were not evaluated."));
                    value.external = false;
                }
                if !value.causes.contains(&word.line) { value.causes.push(word.line); }
                self.unset.remove(name);
                self.vars.insert(name.to_owned(), value);
            }
            return Ok(());
        }
        if at != first_assignment || exporting { return Err("temporary assignments or export form outside the supported subset"); }
        let name = words[0].literal().ok_or("dynamic command name")?;
        if name.contains('/') { return Err("path-qualified or unknown executable"); }
        let args = &words[1..];
        match name.as_str() {
            "set" => {
                for arg in args {
                    let flag = arg.literal().ok_or("dynamic shell option")?;
                    if !matches!(flag.as_str(), "-e" | "-u" | "-eu" | "-ue" | "+e" | "+u") { return Err("unsupported shell option"); }
                    if flag.starts_with('-') && flag.contains('u') { self.nounset = true; }
                    if flag == "+u" { self.nounset = false; }
                }
            }
            "unset" => {
                for arg in args {
                    let var = arg.literal().filter(|v| variable(v)).ok_or("unsupported unset form")?;
                    if special(&var) { return Err("unsetting special shell state is not modeled"); }
                    if self.unset.len() >= MAX_VARS { return Err("unset-variable budget reached"); }
                    if self.vars.len() >= MAX_VARS && !self.vars.contains_key(&var) { return Err("variable budget reached"); }
                    self.unset.insert(var.clone());
                    let mut value = Value::literal(String::new());
                    value.causes.push(line);
                    self.vars.insert(var, value);
                }
            }
            ":" | "true" | "echo" => {
                // These do not alter the modeled variables/files. Expansion still matters.
                for arg in args { if self.value(arg.raw, arg.line)?.external { return Err("command substitution in an argument"); } }
            }
            "cd" => {
                if args.len() != 1 { return Err("unsupported directory change"); }
                let v = self.value(args[0].raw, line)?;
                let path = self.path(&v).ok_or("directory value is unknown")?;
                if !self.dirs.contains(&path) { return Err("directory-change success is unknown"); }
                self.cwd = Some(path);
            }
            "mkdir" | "cp" | "mv" | "rm" | "cat" => self.filesystem(&name, args, line)?,
            _ => return Err("command or control flow is not modeled"),
        }
        Ok(())
    }

    fn path(&self, value: &Value) -> Option<String> {
        let s = value.exact.as_ref()?;
        if s.is_empty() || s.contains(['*', '\n', '\0']) { return None; }
        let path = if s.starts_with('/') { s.clone() } else { format!("{}/{}", self.cwd.as_deref().unwrap_or("<initial folder>"), s) };
        // Do not resolve symlinks or '..' as if the actual filesystem had been observed.
        if path.split('/').any(|p| p == "..") { return None; }
        Some(path.split('/').filter(|p| !p.is_empty() && *p != ".").collect::<Vec<_>>().join("/"))
    }

    fn filesystem(&mut self, command: &str, args: &[Word<'_>], line: u32) -> Result<(), &'static str> {
        if args.len() > MAX_PATHS { return Err("filesystem argument budget reached"); }
        let mut operands = Vec::new();
        let mut options = true;
        let mut no_clobber = false;
        for arg in args {
            if options && arg.literal().as_deref() == Some("--") { options = false; continue; }
            if options && arg.literal().is_some_and(|v| v.starts_with('-')) {
                let option = arg.literal().ok_or("dynamic command option")?;
                let allowed = match command {
                    "mkdir" => matches!(option.as_str(), "-p" | "--parents"),
                    "rm" => matches!(option.as_str(), "-r" | "-R" | "-f" | "-rf" | "-fr" | "-Rf" | "-fR" | "--recursive" | "--force"),
                    "cp" | "mv" => matches!(option.as_str(), "-f" | "-n" | "--force" | "--no-clobber"),
                    _ => false,
                };
                if !allowed { return Err("unsupported command option"); }
                no_clobber |= matches!(option.as_str(), "-n" | "--no-clobber");
                continue;
            }
            let value = self.value(arg.raw, arg.line)?;
            if value.external { return Err("command substitution in a filesystem argument"); }
            if options && value.exact.as_ref().or(value.empty_case.as_ref()).is_some_and(|v| v.starts_with('-')) {
                return Err("an expanded value could be interpreted as a command option");
            }
            if unquoted(arg.raw, "*?[~") { return Err("filename or tilde expansion is not modeled"); }
            // A quoted expansion is one argument. An unquoted expansion may split into many or
            // expand filenames; do not invent a single exact path for that case.
            if unquoted(arg.raw, "$") && value.exact.as_ref().or(value.empty_case.as_ref())
                .is_some_and(|v| v.chars().any(|c| c.is_whitespace() || "*?[".contains(c))) {
                return Err("unquoted variable splitting or filename expansion is not modeled");
            }
            operands.push(value);
        }
        if operands.is_empty() { return Err("missing filesystem operands"); }
        if self.files.len() + self.dirs.len() >= MAX_PATHS { return Err("filesystem model budget reached"); }
        match command {
            "mkdir" => for operand in &operands {
                let path = self.path(operand).ok_or("directory path is unknown")?;
                if self.files.contains_key(&path) { return Err("directory creation conflicts with an earlier file result"); }
                if self.files.len() + self.dirs.len() >= MAX_PATHS { return Err("filesystem model budget reached"); }
                // This is explicitly conditional evidence: successful mkdir, ordinary paths.
                if !self.dirs.contains(&path) { self.dirs.push(path); }
            },
            "cat" => for operand in &operands {
                let path = self.path(operand).ok_or("read path is unknown")?;
                if let Some(file) = self.files.get_mut(&path) { file.read = true; }
            },
            "rm" => for operand in &operands {
                if self.report.findings.len() >= MAX_FINDINGS { return Err("finding budget reached"); }
                if let Some(path) = operand.empty_case.as_deref() {
                    let target = path.trim_end_matches('/');
                    if !operand.causes.is_empty() && matches!(target, "" | "." | "/" | "/home" | "/Users" | "/usr" | "/etc" | "/var" | "/System") && !path.is_empty() {
                        let mut assumptions = operand.assumptions.clone();
                        assumptions.push("The deletion statement is reached. Paths were compared as text; permissions and the tool's protections were not checked.".into());
                        self.report.findings.push(ScriptEffect {
                            rule: "script-broad-delete".into(), line, related_lines: operand.causes.iter().copied().filter(|at| *at < line).collect(),
                            explanation: format!("The deletion target can become {path:?}. That is broader than a specific project subfolder."), assumptions,
                        });
                        return Err("a potentially broad deletion leaves later filesystem state unknown");
                    }
                }
                if let Some(path) = self.path(operand) {
                    let below = format!("{path}/");
                    self.files.retain(|p, _| p != &path && !p.starts_with(&below));
                    self.dirs.retain(|p| p != &path && !p.starts_with(&below));
                    if self.cwd.as_ref().is_some_and(|p| p == &path || p.starts_with(&below)) { return Err("deletion touches the modeled current directory"); }
                }
                else { self.files.clear(); self.dirs.clear(); }
            },
            "cp" | "mv" => {
                if operands.len() != 2 { return Err("only one source and one destination are modeled"); }
                let source = self.path(&operands[0]).ok_or("source path is unknown")?;
                if self.dirs.contains(&source) { return Err("copying or moving directories is not modeled"); }
                let mut dest = self.path(&operands[1]).ok_or("destination path is unknown")?;
                let directory = self.dirs.contains(&dest);
                if directory { dest = format!("{dest}/{}", source.rsplit('/').next().unwrap_or("")); }
                if source == dest { return Err("source and destination name the same lexical path"); }
                if let Some(file) = self.files.get_mut(&source) { file.read = true; }
                if !no_clobber {
                    if let Some(previous) = self.files.get(&dest).filter(|f| !f.read) {
                        let shown = if directory {
                            format!("{}/{}", operands[1].exact.as_deref().unwrap_or("the destination"), source.rsplit('/').next().unwrap_or(""))
                        } else { operands[1].exact.clone().unwrap_or_else(|| "the destination".into()) };
                        self.report.findings.push(ScriptEffect {
                            rule: "script-overwrite".into(), line, related_lines: vec![previous.written],
                            explanation: format!("This {command} can overwrite the earlier result at {shown:?} before it has been read."),
                            assumptions: vec![if directory { "The earlier directory creation and file operations succeed.".into() } else { "The destination is a regular file, not a directory, and both operations succeed.".into() }, "Commands use their usual meanings, without aliases or replacement tools. Actual files and symbolic links (paths pointing elsewhere) were not inspected.".into()],
                        });
                    }
                    if command == "mv" { self.files.remove(&source); }
                    self.files.insert(dest, FileState { written: line, read: false });
                }
            }
            _ => unreachable!(),
        }
        Ok(())
    }
}

fn unquoted(raw: &str, needles: &str) -> bool {
    let mut quote = None;
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        match (quote, c) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => {},
            (_, '\\') => { chars.next(); },
            (None, '\'' | '"') => quote = Some(c),
            (None, c) if needles.contains(c) => return true,
            _ => {},
        }
    }
    false
}

fn substitution_end(chars: &[char], from: usize, backtick: bool) -> Option<usize> {
    let mut i = from + if backtick { 1 } else { 2 };
    let mut depth = 1;
    let mut quote = None;
    while i < chars.len() {
        let c = chars[i];
        if c == '\\' && quote != Some('\'') { i += 2; continue; }
        if quote.is_some() { if quote == Some(c) { quote = None; } }
        else if c == if backtick { '`' } else { ')' } {
            depth -= 1;
            if depth == 0 { return Some(i); }
        } else if !backtick && c == '(' { depth += 1; }
        else if c == '\'' || c == '"' { quote = Some(c); }
        i += 1;
    }
    None
}

pub(crate) fn inspect(text: &str, truncated: bool) -> ScriptAnalysis {
    let start = Instant::now();
    let mut state = State { vars: HashMap::new(), unset: HashSet::new(), files: HashMap::new(), dirs: Vec::new(), cwd: None, nounset: false, report: ScriptAnalysis::default() };
    state.limit("Limited to simple shell statements. No commands were run; no findings is not proof of safety.".into());
    state.limit("Files, symbolic links (paths pointing elsewhere), environment values and command success were not observed. Commands are assumed to use their usual meanings, without aliases or replacement tools. Other shell dialects and effects are outside this check.".into());
    if truncated {
        state.stop(1, "the fetched script is incomplete; effect analysis was not attempted");
        return state.report;
    }
    if text.contains('\0') { state.stop(1, "NUL bytes are not supported"); return state.report; }
    if let Some(shebang) = text.lines().next().and_then(|line| line.strip_prefix("#!")) {
        let mut names = shebang.split_whitespace().map(|s| s.rsplit('/').next().unwrap_or(s));
        let mut name = names.next().unwrap_or("");
        if name == "env" { name = names.next().unwrap_or(""); }
        if !matches!(name, "sh" | "bash" | "dash" | "zsh" | "ksh") {
            state.stop(1, "the declared interpreter is outside the supported shell subset"); return state.report;
        }
    }
    let parsed = shell_text::scan(text);
    let mut words = Vec::new();
    for token in &parsed.tokens {
        let at = match token { Token::Word(w) => w.line, Token::Op(_, line) => *line };
        if start.elapsed() >= BUDGET || state.report.statements >= MAX_STEPS || state.report.findings.len() >= MAX_FINDINGS {
            state.stop(at, "inspection budget reached"); break;
        }
        match token {
            Token::Word(word) => words.push(word.clone()),
            Token::Op(";" | "\n", _) => {
                if parsed.error.as_ref().is_some_and(|(line, _)| words.iter().any(|w| w.line >= *line)) { break; }
                if let Err(reason) = state.statement(&words) { state.stop(words.first().map_or(at, |w| w.line), reason); break; }
                if !words.is_empty() { state.report.statements += 1; }
                words.clear();
            }
            Token::Op(_, _) => { state.stop(at, "control flow, pipelines, redirection or compound syntax is not modeled"); break; }
        }
    }
    if state.report.stopped_at.is_none() {
        if let Some((line, reason)) = parsed.error { state.stop(line, reason); }
        else if start.elapsed() >= BUDGET { state.stop(words.first().map_or(1, |w| w.line), "inspection budget reached"); }
        else if !words.is_empty() {
            match state.statement(&words) {
                Ok(()) => state.report.statements += 1,
                Err(reason) => state.stop(words[0].line, reason),
            }
        }
    }
    state.report.findings.truncate(MAX_FINDINGS);
    state.report
}

//! `terminal.assess`: what typed input would do before it runs. Two parts, both plain code:
//!
//! - kind: shell command, question (ask) or unsure, from explicit signs, whether the first word
//!   resolves in that terminal's shell (alias, function, builtin, PATH), shell syntax and how much
//!   the line reads like a sentence;
//! - risk: the line is tokenized (quotes, escapes, substitutions), split into commands, each
//!   unwrapped (assignments, sudo, env, xargs, `sh -c`, eval, ... to depth 8) and classified by its
//!   program; the highest class wins. The model never decides this.

use crate::marks::ShellEnv;
use crate::threat;
use cc_protocol::contracts::terminal::{Assessment, GlobMatches};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Shell builtins and keywords (zsh and bash): they resolve without PATH.
pub const BUILTINS: &[&str] = &[
    ".", ":", "[", "[[", "alias", "autoload", "bg", "bind", "bindkey", "break", "builtin", "case", "cd", "chdir", "command",
    "compgen", "complete", "continue", "declare", "dirs", "disown", "do", "done", "echo", "elif", "else", "emulate", "esac",
    "eval", "exec", "exit", "export", "false", "fc", "fg", "fi", "for", "function", "getopts", "hash", "help", "history", "if",
    "in", "jobs", "kill", "let", "local", "logout", "popd", "print", "printf", "pushd", "pwd", "read", "readonly", "rehash",
    "return", "select", "set", "setopt", "shift", "shopt", "source", "suspend", "test", "then", "time", "times", "trap", "true",
    "type", "typeset", "ulimit", "umask", "unalias", "unfunction", "unset", "unsetopt", "until", "wait", "whence", "where",
    "which", "while", "zle", "zmodload", "zstyle",
];

const MAX_DEPTH: usize = 8;
const WALK_ENTRIES: usize = 20_000;
const WALK_TIME: Duration = Duration::from_millis(200);

// ---------------------------------------------------------------------------------------------
// Tokens

#[derive(Debug, Clone, Default)]
pub struct Word {
    pub text: String,
    pub quoted: bool,
    /// Holds a variable or arithmetic expansion.
    pub var: bool,
    /// Holds a command substitution.
    pub subst: bool,
    /// Holds an unquoted glob character.
    pub glob: bool,
}

impl Word {
    fn dynamic(&self) -> bool {
        self.var || self.subst
    }
}

#[derive(Debug, Clone)]
enum Tok {
    Word(Word),
    Op(&'static str),
}

const OPS: &[&str] =
    &["&>>", "<<<", "<<-", ";;", "&&", "||", "|&", ">>", "<<", ">&", "<&", ">|", "&>", "<>", ";", "&", "|", "<", ">", "(", ")"];

fn is_redirect(op: &str) -> bool {
    matches!(op, "&>>" | "<<<" | "<<-" | ">>" | "<<" | ">&" | "<&" | ">|" | "&>" | "<>" | "<" | ">")
}

/// The index after the `)` matching the `(` at `open`.
fn matching(chars: &[char], open: usize) -> Result<usize, String> {
    let mut depth = 0;
    let mut i = open;
    while i < chars.len() {
        match chars[i] {
            '\\' => i += 1,
            '\'' => {
                i += 1;
                while i < chars.len() && chars[i] != '\'' {
                    i += 1;
                }
            }
            '"' => {
                i += 1;
                while i < chars.len() && chars[i] != '"' {
                    if chars[i] == '\\' {
                        i += 1;
                    }
                    i += 1;
                }
            }
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Ok(i + 1);
                }
            }
            _ => {}
        }
        i += 1;
    }
    Err("unterminated substitution".into())
}

fn dollar(chars: &[char], i: usize, word: &mut Word) -> Result<usize, String> {
    let take = |end: usize, word: &mut Word| {
        word.text.extend(&chars[i..end.min(chars.len())]);
        end
    };
    match chars.get(i + 1) {
        Some('(') => {
            let end = matching(chars, i + 1)?;
            if chars.get(i + 2) == Some(&'(') {
                word.var = true;
            } else {
                word.subst = true;
            }
            Ok(take(end, word))
        }
        Some('{') => {
            let close = chars[i..].iter().position(|c| *c == '}').ok_or("unterminated ${")?;
            word.var = true;
            Ok(take(i + close + 1, word))
        }
        Some('\'') => {
            // $'...': ANSI-C quoting, literal text; `\x72\x6d` is `rm`, so the escapes are decoded.
            let mut j = i + 2;
            while j < chars.len() && chars[j] != '\'' {
                if chars[j] == '\\' && j + 1 < chars.len() {
                    j += 1;
                    let digits = |from: usize, radix: u32, max: usize| {
                        let count = chars[from..].iter().take(max).take_while(|c| c.is_digit(radix)).count();
                        let value = u32::from_str_radix(&chars[from..from + count].iter().collect::<String>(), radix).ok();
                        (count, value.and_then(char::from_u32))
                    };
                    let (skip, decoded) = match chars[j] {
                        'n' => (0, Some('\n')),
                        't' => (0, Some('\t')),
                        'e' | 'E' => (0, Some('\u{1b}')),
                        'x' => digits(j + 1, 16, 2),
                        'u' => digits(j + 1, 16, 4),
                        'U' => digits(j + 1, 16, 8),
                        '0'..='7' => {
                            let (count, value) = digits(j, 8, 3);
                            (count.saturating_sub(1), value)
                        }
                        other => (0, Some(other)),
                    };
                    word.text.push(decoded.unwrap_or(chars[j]));
                    j += skip;
                } else {
                    word.text.push(chars[j]);
                }
                j += 1;
            }
            if j >= chars.len() {
                return Err("unterminated quote".into());
            }
            word.quoted = true;
            Ok(j + 1)
        }
        Some(c) if c.is_ascii_alphabetic() || *c == '_' => {
            let mut j = i + 1;
            while j < chars.len() && (chars[j].is_ascii_alphanumeric() || chars[j] == '_') {
                j += 1;
            }
            word.var = true;
            Ok(take(j, word))
        }
        Some(c) if c.is_ascii_digit() || "?#@*!$-".contains(*c) => {
            word.var = true;
            Ok(take(i + 2, word))
        }
        _ => {
            word.text.push('$');
            Ok(i + 1)
        }
    }
}

fn backtick(chars: &[char], i: usize, word: &mut Word) -> Result<usize, String> {
    let mut j = i + 1;
    while j < chars.len() && chars[j] != '`' {
        if chars[j] == '\\' {
            j += 1;
        }
        j += 1;
    }
    if j >= chars.len() {
        return Err("unterminated backtick".into());
    }
    word.subst = true;
    word.text.extend(&chars[i..=j]);
    Ok(j + 1)
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let chars: Vec<char> = src.chars().collect();
    let n = chars.len();
    let mut toks = Vec::new();
    let mut word = Word::default();
    let mut in_word = false;
    let mut heredocs: Vec<(String, bool)> = Vec::new();
    let mut want_heredoc: Option<bool> = None;
    let mut i = 0;
    let flush = |toks: &mut Vec<Tok>, word: &mut Word, in_word: &mut bool, want: &mut Option<bool>, docs: &mut Vec<(String, bool)>| {
        if *in_word {
            if let Some(strip) = want.take() {
                docs.push((word.text.clone(), strip));
            }
            toks.push(Tok::Word(std::mem::take(word)));
            *in_word = false;
        }
    };
    while i < n {
        let c = chars[i];
        match c {
            ' ' | '\t' => {
                flush(&mut toks, &mut word, &mut in_word, &mut want_heredoc, &mut heredocs);
                i += 1;
            }
            '\n' => {
                flush(&mut toks, &mut word, &mut in_word, &mut want_heredoc, &mut heredocs);
                toks.push(Tok::Op("\n"));
                i += 1;
                // Here-document bodies are data, not commands.
                while !heredocs.is_empty() && i < n {
                    let end = chars[i..].iter().position(|c| *c == '\n').map_or(n, |p| i + p);
                    let line: String = chars[i..end].iter().collect();
                    let (delimiter, strip) = &heredocs[0];
                    let line = if *strip { line.trim_start_matches('\t') } else { line.as_str() };
                    if line == delimiter {
                        heredocs.remove(0);
                    }
                    i = end + 1;
                }
            }
            '#' if !in_word => {
                while i < n && chars[i] != '\n' {
                    i += 1;
                }
            }
            '\\' => {
                if i + 1 < n {
                    if chars[i + 1] != '\n' {
                        word.text.push(chars[i + 1]);
                        word.quoted = true;
                        in_word = true;
                    }
                    i += 2;
                } else {
                    i += 1;
                }
            }
            '\'' => {
                let close = chars[i + 1..].iter().position(|c| *c == '\'').ok_or("unterminated quote")?;
                word.text.extend(&chars[i + 1..i + 1 + close]);
                word.quoted = true;
                in_word = true;
                i += close + 2;
            }
            '"' => {
                i += 1;
                loop {
                    if i >= n {
                        return Err("unterminated quote".into());
                    }
                    match chars[i] {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '\\' if i + 1 < n && matches!(chars[i + 1], '$' | '`' | '"' | '\\' | '\n') => {
                            if chars[i + 1] != '\n' {
                                word.text.push(chars[i + 1]);
                            }
                            i += 2;
                        }
                        '$' => i = dollar(&chars, i, &mut word)?,
                        '`' => i = backtick(&chars, i, &mut word)?,
                        other => {
                            word.text.push(other);
                            i += 1;
                        }
                    }
                }
                word.quoted = true;
                in_word = true;
            }
            '$' => {
                i = dollar(&chars, i, &mut word)?;
                in_word = true;
            }
            '`' => {
                i = backtick(&chars, i, &mut word)?;
                in_word = true;
            }
            '*' | '?' | '[' => {
                word.glob = true;
                word.text.push(c);
                in_word = true;
                i += 1;
            }
            ';' | '&' | '|' | '<' | '>' | '(' | ')' => {
                // `2>` and friends: the digits are a file descriptor, not a word.
                let fd = (c == '<' || c == '>')
                    && in_word
                    && !word.quoted
                    && !word.dynamic()
                    && !word.text.is_empty()
                    && word.text.chars().all(|d| d.is_ascii_digit());
                if fd {
                    word = Word::default();
                    in_word = false;
                } else {
                    flush(&mut toks, &mut word, &mut in_word, &mut want_heredoc, &mut heredocs);
                }
                let rest: String = chars[i..(i + 3).min(n)].iter().collect();
                let op = OPS.iter().find(|op| rest.starts_with(**op)).copied().unwrap_or(";");
                if op == "<<" || op == "<<-" {
                    want_heredoc = Some(op == "<<-");
                }
                toks.push(Tok::Op(op));
                i += op.len();
            }
            _ => {
                word.text.push(c);
                in_word = true;
                i += 1;
            }
        }
    }
    flush(&mut toks, &mut word, &mut in_word, &mut want_heredoc, &mut heredocs);
    Ok(toks)
}

#[derive(Debug, Clone, Default)]
pub struct Cmd {
    pub words: Vec<Word>,
    pub redirects: Vec<(String, Word)>,
    /// Its standard input comes from a pipe.
    pub piped_in: bool,
}

/// Split a script into its simple commands.
pub fn parse(src: &str) -> Result<Vec<Cmd>, String> {
    let mut cmds = Vec::new();
    let mut current = Cmd::default();
    let mut piped = false;
    let mut toks = lex(src)?.into_iter();
    while let Some(tok) = toks.next() {
        match tok {
            Tok::Word(word) => current.words.push(word),
            Tok::Op(op) if is_redirect(op) => match toks.next() {
                Some(Tok::Word(target)) => current.redirects.push((op.to_owned(), target)),
                _ => return Err("redirect without a target".into()),
            },
            Tok::Op(op) => {
                let pipe = op == "|" || op == "|&";
                if !current.words.is_empty() || !current.redirects.is_empty() {
                    current.piped_in = piped;
                    cmds.push(std::mem::take(&mut current));
                } else if pipe {
                    return Err("pipe without a command".into());
                }
                piped = pipe;
            }
        }
    }
    if !current.words.is_empty() || !current.redirects.is_empty() {
        current.piped_in = piped;
        cmds.push(current);
    } else if piped {
        return Err("pipe without a command".into());
    }
    Ok(cmds)
}

// ---------------------------------------------------------------------------------------------
// Resolution

/// Where a terminal's names come from.
pub struct Shell<'a> {
    pub env: &'a ShellEnv,
    pub cwd: &'a Path,
}

pub enum Resolved {
    Alias(String),
    Function,
    Builtin,
    File(PathBuf),
}

impl Shell<'_> {
    pub fn path_dirs(&self) -> Vec<PathBuf> {
        let path = self.env.path.clone().or_else(|| std::env::var("PATH").ok()).unwrap_or_default();
        path.split(':').filter(|d| !d.is_empty()).map(PathBuf::from).collect()
    }

    pub fn resolve(&self, name: &str) -> Option<Resolved> {
        if name.is_empty() {
            return None;
        }
        if name.contains('/') {
            let path = expand(name, self.cwd);
            return executable(&path).then_some(Resolved::File(path));
        }
        if let Some(value) = self.env.aliases.get(name) {
            return Some(Resolved::Alias(value.clone()));
        }
        if self.env.functions.contains(name) {
            return Some(Resolved::Function);
        }
        if BUILTINS.contains(&name) {
            return Some(Resolved::Builtin);
        }
        self.which(name).map(Resolved::File)
    }

    pub fn which(&self, name: &str) -> Option<PathBuf> {
        self.path_dirs().into_iter().map(|dir| dir.join(name)).find(|p| executable(p))
    }
}

fn executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
}

/// `~` and `~/x` to the home folder; relative paths against `cwd`.
pub fn expand(text: &str, cwd: &Path) -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_default();
    let path = if text == "~" {
        PathBuf::from(&home)
    } else if let Some(rest) = text.strip_prefix("~/") {
        Path::new(&home).join(rest)
    } else {
        PathBuf::from(text)
    };
    if path.is_absolute() { path } else { cwd.join(path) }
}

fn basename(text: &str) -> &str {
    text.rsplit('/').next().unwrap_or(text)
}

// ---------------------------------------------------------------------------------------------
// Risk

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Risk {
    Read,
    Write,
    Network,
    Delete,
    Admin,
    Unknown,
}

impl Risk {
    pub fn name(self) -> &'static str {
        match self {
            Risk::Read => "read",
            Risk::Write => "write",
            Risk::Network => "network",
            Risk::Delete => "delete",
            Risk::Admin => "admin",
            Risk::Unknown => "unknown",
        }
    }
}

#[derive(Default)]
struct Analysis {
    risk: Option<Risk>,
    reasons: Vec<String>,
    /// Path arguments of commands that write or delete.
    targets: Vec<Word>,
    /// The first command's program: name and resolved path.
    program: Option<String>,
    first_done: bool,
}

impl Analysis {
    fn add(&mut self, risk: Risk, reason: impl Into<String>) {
        self.risk = Some(self.risk.map_or(risk, |r| r.max(risk)));
        let reason = reason.into();
        if !reason.is_empty() && !self.reasons.contains(&reason) {
            self.reasons.push(reason);
        }
    }
}

fn is_assignment(word: &Word) -> bool {
    let Some((name, _)) = word.text.split_once('=') else { return false };
    !name.is_empty()
        && name.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '+')
}

fn sensitive_variable(name: &str) -> bool {
    let name = name.trim_end_matches('+');
    matches!(name, "PATH" | "IFS" | "ENV" | "BASH_ENV" | "PROMPT_COMMAND" | "LD_PRELOAD" | "LD_LIBRARY_PATH" | "ZDOTDIR")
        || name.starts_with("DYLD_")
}

const SYSTEM_PATHS: &[&str] = &["/System", "/usr", "/bin", "/sbin", "/etc", "/Library", "/private", "/var", "/boot", "/lib", "/opt/homebrew/Cellar"];

fn system_path(text: &str) -> bool {
    text == "/" || SYSTEM_PATHS.iter().any(|p| text == *p || text.starts_with(&format!("{p}/")))
}

fn analyze_script(src: &str, depth: usize, shell: &Shell, out: &mut Analysis) {
    if depth > MAX_DEPTH {
        out.add(Risk::Unknown, "nested too deeply");
        return;
    }
    match parse(src) {
        Ok(cmds) => {
            for cmd in cmds {
                analyze_cmd(&cmd.words, &cmd.redirects, cmd.piped_in, depth, shell, out, &mut Vec::new());
            }
        }
        Err(_) => out.add(Risk::Unknown, "cannot parse"),
    }
}

fn args_text(words: &[Word]) -> Vec<&str> {
    words.iter().map(|w| w.text.as_str()).collect()
}

/// Skip leading options of a wrapper; `with_value` lists the options that take the next word.
fn skip_options<'a>(words: &'a [Word], with_value: &[&str]) -> &'a [Word] {
    let mut i = 0;
    while i < words.len() {
        let text = words[i].text.as_str();
        if text == "--" {
            return &words[i + 1..];
        }
        if !text.starts_with('-') || text == "-" {
            break;
        }
        i += if with_value.contains(&text) { 2 } else { 1 };
    }
    &words[i.min(words.len())..]
}

fn analyze_cmd(
    words: &[Word],
    redirects: &[(String, Word)],
    piped_in: bool,
    depth: usize,
    shell: &Shell,
    out: &mut Analysis,
    expanded: &mut Vec<String>,
) {
    if depth > MAX_DEPTH {
        out.add(Risk::Unknown, "nested too deeply");
        return;
    }
    for (op, target) in redirects {
        if target.subst {
            out.add(Risk::Unknown, "command substitution");
        }
        let writes = matches!(op.as_str(), ">" | ">>" | ">|" | "&>" | "&>>" | "<>")
            || (op == ">&" && !target.text.chars().all(|c| c.is_ascii_digit() || c == '-'));
        if writes && !matches!(target.text.as_str(), "/dev/null" | "/dev/stdout" | "/dev/stderr" | "/dev/tty") {
            if target.dynamic() {
                out.add(Risk::Unknown, "writes to a variable path");
            } else {
                out.add(Risk::Write, format!("writes {}", target.text));
                out.targets.push(target.clone());
            }
        }
    }
    if words.iter().any(|w| w.subst) {
        out.add(Risk::Unknown, "command substitution");
    }
    // Leading VAR=value assignments.
    let mut start = 0;
    while start < words.len() && is_assignment(&words[start]) {
        let name = words[start].text.split_once('=').map(|(n, _)| n).unwrap_or("");
        if sensitive_variable(name) {
            out.add(Risk::Unknown, format!("changes {}", name.trim_end_matches('+')));
        }
        start += 1;
    }
    let mut words = &words[start..];
    // Shell keywords around commands (if/then/do ...) are not programs.
    while let Some(first) = words.first()
        && !first.quoted
        && matches!(first.text.as_str(), "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" | "{" | "}" | "fi" | "done" | "esac")
    {
        words = &words[1..];
    }
    let Some(program) = words.first() else {
        out.add(Risk::Read, "");
        return;
    };
    if program.dynamic() {
        out.add(Risk::Unknown, "variable in command position");
        return;
    }
    if program.glob {
        out.add(Risk::Unknown, "glob in command position");
        return;
    }
    let text = program.text.as_str();
    let name = basename(text);
    let args = &words[1..];

    // Aliases (once each), unless the name was quoted or reached through `command`/`builtin`.
    if !program.quoted
        && !text.contains('/')
        && !expanded.iter().any(|e| e == text)
        && let Some(value) = shell.env.aliases.get(text)
    {
        expanded.push(text.to_owned());
        match parse(value) {
            Ok(mut cmds) if !cmds.is_empty() => {
                let last = cmds.len() - 1;
                cmds[last].words.extend(args.iter().cloned());
                cmds[last].redirects.extend(redirects.iter().cloned());
                if last == 0 {
                    cmds[0].piped_in |= piped_in;
                }
                for cmd in &cmds {
                    analyze_cmd(&cmd.words, &cmd.redirects, cmd.piped_in, depth + 1, shell, out, expanded);
                }
            }
            _ => out.add(Risk::Unknown, format!("alias `{text}` cannot be read")),
        }
        return;
    }

    let recurse = |rest: &[Word], out: &mut Analysis, expanded: &mut Vec<String>| {
        if rest.is_empty() {
            out.add(Risk::Read, "");
        } else {
            analyze_cmd(rest, &[], piped_in, depth + 1, shell, out, expanded);
        }
    };
    match name {
        "sudo" | "doas" | "run0" | "pkexec" => {
            out.add(Risk::Admin, "runs as root");
            let rest = skip_options(args, &["-u", "-g", "-h", "-p", "-C", "-U", "-r", "-t", "-T", "-D", "-R"]);
            let rest = &rest[rest.iter().take_while(|w| is_assignment(w)).count()..];
            return recurse(rest, out, expanded);
        }
        "env" => {
            let mut rest = skip_options(args, &["-u", "-C", "-P", "--unset", "--chdir"]);
            if args.iter().any(|w| w.text == "-S" || w.text.starts_with("--split-string")) {
                out.add(Risk::Unknown, "env -S");
                return;
            }
            while let Some(first) = rest.first()
                && is_assignment(first)
            {
                let name = first.text.split_once('=').map(|(n, _)| n).unwrap_or("");
                if sensitive_variable(name) {
                    out.add(Risk::Unknown, format!("changes {name}"));
                }
                rest = &rest[1..];
            }
            return recurse(rest, out, expanded);
        }
        "command" | "builtin" => {
            if args.first().is_some_and(|w| w.text == "-v" || w.text == "-V") {
                out.add(Risk::Read, "");
                return;
            }
            let rest = skip_options(args, &[]);
            // `command ls` skips aliases: analyze the name as quoted.
            let mut rest = rest.to_vec();
            if let Some(first) = rest.first_mut() {
                first.quoted = true;
            }
            return recurse(&rest, out, expanded);
        }
        "exec" => return recurse(skip_options(args, &["-a"]), out, expanded),
        "nice" => return recurse(skip_options(args, &["-n"]), out, expanded),
        "nohup" | "time" | "caffeinate" | "chronic" => return recurse(skip_options(args, &["-t", "-w"]), out, expanded),
        "timeout" | "gtimeout" => {
            let rest = skip_options(args, &["-s", "-k", "--signal", "--kill-after"]);
            return recurse(rest.get(1..).unwrap_or(&[]), out, expanded);
        }
        "stdbuf" => return recurse(skip_options(args, &["-i", "-o", "-e"]), out, expanded),
        "setsid" | "unbuffer" | "ionice" | "busybox" => return recurse(skip_options(args, &["-c", "-n"]), out, expanded),
        // `arch -x86_64 rm ...` runs the command; bare `arch` prints the architecture.
        "arch" if !args.is_empty() => return recurse(skip_options(args, &["-arch", "-e", "-d"]), out, expanded),
        // `flock <file> <command>` and `script [-q] <file> <command>` run what follows the file.
        "flock" | "script" => {
            let rest = skip_options(args, &["-w", "-E", "-t", "-T", "-F"]);
            return recurse(rest.get(1..).unwrap_or(&[]), out, expanded);
        }
        "parallel" => {
            out.add(Risk::Unknown, "runs commands in parallel");
            return;
        }
        "xargs" => {
            let rest = skip_options(args, &["-I", "-L", "-n", "-P", "-s", "-d", "-E", "-a", "-J", "-R", "-S"]);
            return recurse(rest, out, expanded);
        }
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" => {
            let mut i = 0;
            while i < args.len() && args[i].text.starts_with('-') {
                let flag = &args[i].text;
                if !flag.starts_with("--") && flag.contains('c') {
                    match args.get(i + 1) {
                        Some(script) if !script.dynamic() => analyze_script(&script.text, depth + 1, shell, out),
                        Some(_) => out.add(Risk::Unknown, "runs dynamic code"),
                        None => out.add(Risk::Unknown, "cannot parse"),
                    }
                    return;
                }
                i += 1;
            }
            if i < args.len() {
                out.add(Risk::Write, "runs a script");
            } else if piped_in {
                out.add(Risk::Unknown, "pipes into a shell");
            } else {
                out.add(Risk::Read, "");
            }
            note_first(out, name, shell);
            return;
        }
        "eval" => {
            if args.iter().any(Word::dynamic) {
                out.add(Risk::Unknown, "eval of dynamic text");
            } else {
                analyze_script(&args_text(args).join(" "), depth + 1, shell, out);
            }
            return;
        }
        "source" | "." => {
            out.add(Risk::Unknown, "sources a script");
            return;
        }
        "trap" => {
            out.add(Risk::Unknown, "sets a trap");
            return;
        }
        _ => {}
    }

    note_first(out, name, shell);
    if !text.contains('/') && shell.resolve(text).is_none() {
        out.add(Risk::Unknown, format!("`{name}` not found"));
        return;
    }
    if text.contains('/')
        && let Some((risk, reason)) = skills_script(&expand(text, shell.cwd), args)
    {
        out.add(risk, reason);
        return;
    }
    // A program named by its path is only judged by its name when it is the system's own copy:
    // `./ls` or `/tmp/readonly` could be anything.
    if text.contains('/') && !system_program(&expand(text, shell.cwd)) {
        out.add(Risk::Write, format!("runs {text}"));
        return;
    }
    let (risk, reason, files) = classify(name, args, piped_in, shell, depth, out, expanded);
    out.add(risk, reason);
    if files && matches!(risk, Risk::Write | Risk::Delete) {
        out.targets.extend(args.iter().filter(|w| !w.text.starts_with('-') || w.text == "-").cloned());
    }
}

/// Record the first command's program (once). Standard tool names always run the real tool.
fn note_first(out: &mut Analysis, name: &str, shell: &Shell) {
    if out.first_done {
        return;
    }
    out.first_done = true;
    let file = match shell.resolve(name) {
        Some(Resolved::File(path)) => Some(path),
        Some(Resolved::Alias(_)) => shell.which(name),
        _ => None,
    };
    out.program = Some(file.map_or_else(|| name.to_owned(), |path| path.to_string_lossy().into_owned()));
}

fn short_flag(args: &[Word], letter: char) -> bool {
    args.iter().any(|w| w.text.starts_with('-') && !w.text.starts_with("--") && w.text[1..].contains(letter))
}

fn has(args: &[Word], flag: &str) -> bool {
    args.iter().any(|w| w.text == flag || w.text.starts_with(&format!("{flag}=")))
}

/// The first positional argument (a subcommand).
fn sub(args: &[Word]) -> &str {
    args.iter().map(|w| w.text.as_str()).find(|t| !t.starts_with('-')).unwrap_or("")
}

const READ: &[&str] = &[
    "ls", "ll", "la", "cat", "bat", "head", "tail", "less", "more", "most", "grep", "egrep", "fgrep", "rg", "ag", "ack", "wc",
    "which", "whereis", "whence", "where", "type", "file", "stat", "du", "df", "ps", "pgrep", "top", "htop", "btop", "pwd",
    "echo", "print", "printf", "diff", "cmp", "comm", "sort", "uniq", "cut", "tr", "awk", "gawk", "jq", "yq", "tree", "date",
    "cal", "uptime", "whoami", "id", "groups", "hostname", "uname", "printenv", "history", "jobs", "true", "false", "test",
    "[", "[[", ":", "basename", "dirname", "realpath", "readlink", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "cksum",
    "hexdump", "xxd", "od", "strings", "nl", "column", "fold", "fmt", "rev", "tac", "seq", "sleep", "clear", "reset", "tput",
    "lsof", "netstat", "ifconfig", "sw_vers", "man", "info", "help", "whatis", "apropos", "locate", "mdfind", "fd", "cd",
    "pushd", "popd", "dirs", "alias", "unalias", "set", "unset", "setopt", "unsetopt", "shopt", "typeset", "declare", "local",
    "readonly", "read", "wait", "fg", "bg", "disown", "exit", "logout", "hash", "rehash", "ulimit", "bindkey", "zstyle",
    "autoload", "vm_stat", "iostat", "vmstat", "free", "nproc", "arch", "env", "tldr", "z", "zoxide", "fzf", "glow", "delta",
    "watch", "yes", "time", "uptime", "w", "who", "last", "nslookup", "cal", "bc", "expr", "let", "true", "pbpaste", "say",
    // Diagnostics that only print what they find.
    "system_profiler", "ioreg", "journalctl", "dmesg", "lsblk", "lscpu", "ss", "mdls", "otool", "nm", "lipo", "kextstat",
    "memory_pressure", "footprint", "vmmap", "leaks", "heap", "nettop", "zprint", "getconf", "locale", "tty", "nvidia-smi",
];

const EDITORS: &[&str] = &["nano", "pico", "vi", "vim", "nvim", "edit", "micro", "emacs", "code", "subl", "hx"];

const NETWORK: &[&str] = &[
    "curl", "wget", "ssh", "scp", "sftp", "rsync", "nc", "ncat", "netcat", "telnet", "ftp", "mosh", "socat", "http", "https",
    "aria2c", "ping", "traceroute", "dig", "host", "whois", "npx", "bunx", "pnpx", "gh",
];

const ADMIN: &[&str] = &[
    "su", "launchctl", "systemctl", "service", "shutdown", "reboot", "halt", "poweroff", "mount", "umount", "diskutil",
    "fdisk", "mkfs", "kextload", "kextunload", "csrutil", "spctl", "nvram", "scutil", "dscl", "dseditgroup", "networksetup",
    "systemsetup", "pfctl", "sysadminctl", "softwareupdate", "passwd", "visudo", "chroot", "kmutil", "tmutil", "fsck",
];

/// The class of one (unwrapped) command; `files` says its arguments are paths it writes or deletes.
fn classify(
    name: &str,
    args: &[Word],
    piped_in: bool,
    shell: &Shell,
    depth: usize,
    out: &mut Analysis,
    expanded: &mut Vec<String>,
) -> (Risk, String, bool) {
    let r = |risk: Risk, reason: &str| (risk, reason.to_owned(), false);
    let files = |risk: Risk, reason: &str| (risk, reason.to_owned(), true);
    match name {
        "rm" | "rmdir" | "unlink" | "shred" | "srm" | "trash" | "truncate" => files(Risk::Delete, "deletes files"),
        "find" => {
            if has(args, "-delete") {
                files(Risk::Delete, "deletes files")
            } else if ["-fprint", "-fprint0", "-fprintf", "-fls"].iter().any(|f| has(args, f)) {
                r(Risk::Write, "writes files")
            } else {
                // Each `-exec <command> {} ;` is as risky as its command.
                let mut i = 0;
                while i < args.len() {
                    if matches!(args[i].text.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
                        let end = args[i + 1..].iter().position(|w| w.text == ";" || w.text == "+").map_or(args.len(), |at| i + 1 + at);
                        let command: Vec<Word> = args[i + 1..end].iter().filter(|w| w.text != "{}").cloned().collect();
                        if command.is_empty() {
                            out.add(Risk::Unknown, "find -exec");
                        } else {
                            analyze_cmd(&command, &[], false, depth + 1, shell, out, expanded);
                        }
                        i = end;
                    }
                    i += 1;
                }
                r(Risk::Read, "")
            }
        }
        "git" => git(args),
        "sed" | "perl" if short_flag(args, 'i') || has(args, "--in-place") => files(Risk::Write, "edits files in place"),
        "sed" => r(Risk::Read, ""),
        // awk's system(), pipes to commands and getline from commands run shell code.
        "awk" | "gawk" | "mawk" | "nawk" => {
            let program = args.iter().find(|w| !w.text.starts_with('-')).map(|w| w.text.as_str()).unwrap_or("");
            for (at, _) in program.match_indices("system(") {
                let rest = &program[at + 7..];
                match rest.trim_start().strip_prefix('"').and_then(|r| r.split_once('"')) {
                    Some((script, _)) => analyze_script(script, depth + 1, shell, out),
                    None => out.add(Risk::Unknown, "awk runs dynamic commands"),
                }
            }
            if program.contains("| getline") || program.contains("|getline") || program.contains("print |") || program.contains("printf |") || program.contains("|&") {
                out.add(Risk::Unknown, "awk runs commands");
            }
            if program.contains("> \"") || program.contains(">\"") { r(Risk::Write, "writes files") } else { r(Risk::Read, "") }
        }
        "python" | "python3" | "node" | "perl" | "ruby" | "php" | "deno" | "lua" | "osascript" => {
            if ["-c", "-e", "--eval", "-p", "--print", "-E"].iter().any(|f| has(args, f)) {
                r(Risk::Unknown, "runs inline code")
            } else if args.iter().any(|w| !w.text.starts_with('-')) {
                r(Risk::Write, "runs a script")
            } else if piped_in {
                r(Risk::Unknown, "pipes into an interpreter")
            } else {
                r(Risk::Read, "")
            }
        }
        "export" => {
            for word in args {
                let name = word.text.split_once('=').map_or(word.text.as_str(), |(n, _)| n);
                if sensitive_variable(name) && word.text.contains('=') {
                    return r(Risk::Unknown, &format!("changes {name}"));
                }
            }
            r(Risk::Read, "")
        }
        "chown" | "chgrp" | "chmod" | "chflags" | "xattr" => {
            if args.iter().any(|w| system_path(&expand(&w.text, shell.cwd).to_string_lossy())) {
                r(Risk::Admin, "changes system files")
            } else {
                files(Risk::Write, "changes file permissions")
            }
        }
        "kill" | "killall" | "pkill" => r(Risk::Write, "stops processes"),
        "mv" => files(Risk::Write, "moves files"),
        // Options that run a command of their choosing.
        "tar" | "gtar" | "bsdtar" if args.iter().any(|w| ["--checkpoint-action", "--use-compress-program", "--to-command", "--info-script", "--new-volume-script", "-I"].iter().any(|f| w.text == *f || w.text.starts_with(&format!("{f}=")))) => {
            r(Risk::Unknown, "tar runs a command")
        }
        "zip" if has(args, "-TT") || has(args, "--unzip-command") => r(Risk::Unknown, "zip runs a command"),
        "cp" | "ln" | "mkdir" | "touch" | "tee" | "install" | "ditto" | "unzip" | "tar" | "gunzip" | "gzip" | "zip" | "patch" => {
            files(Risk::Write, "writes files")
        }
        "dd" => {
            if args.iter().any(|w| w.text.starts_with("of=/dev/")) {
                r(Risk::Admin, "writes a device")
            } else {
                r(Risk::Write, "writes files")
            }
        }
        "defaults" => match sub(args) {
            "read" | "domains" | "find" | "export" => r(Risk::Read, ""),
            _ => r(Risk::Write, "changes settings"),
        },
        "sysctl" if args.iter().any(|w| w.text == "-w" || w.text.contains('=')) => r(Risk::Admin, "changes the system"),
        "sysctl" | "pmset" if !args.iter().any(|w| !w.text.starts_with('-')) || has(args, "-g") => r(Risk::Read, ""),
        "crontab" => {
            if has(args, "-l") {
                r(Risk::Read, "")
            } else if has(args, "-r") {
                r(Risk::Delete, "deletes the crontab")
            } else {
                r(Risk::Write, "changes scheduled jobs")
            }
        }
        "brew" => match sub(args) {
            "list" | "ls" | "info" | "search" | "deps" | "outdated" | "doctor" | "config" | "leaves" | "uses" | "desc" | "home"
            | "--version" | "" => r(Risk::Read, ""),
            "install" | "reinstall" | "upgrade" | "update" | "tap" | "fetch" | "bundle" => r(Risk::Network, "installs packages"),
            "uninstall" | "remove" | "rm" | "untap" | "cleanup" | "autoremove" => r(Risk::Delete, "removes packages"),
            _ => r(Risk::Write, "changes packages"),
        },
        "npm" | "pnpm" | "yarn" | "bun" => match sub(args) {
            "ls" | "list" | "view" | "info" | "outdated" | "why" | "help" | "config" | "--version" | "-v" => r(Risk::Read, ""),
            "" if name == "yarn" => r(Risk::Network, "installs packages"),
            "" => r(Risk::Read, ""),
            "install" | "i" | "add" | "ci" | "update" | "up" | "upgrade" | "remove" | "rm" | "uninstall" | "publish" | "dlx"
            | "create" | "init" => r(Risk::Network, "installs packages"),
            _ => r(Risk::Write, "runs project scripts"),
        },
        "pip" | "pip3" | "pipx" | "uv" | "poetry" | "gem" | "conda" | "mamba" => match sub(args) {
            "list" | "show" | "freeze" | "check" | "search" | "help" | "--version" | "" => r(Risk::Read, ""),
            "run" => r(Risk::Write, "runs project scripts"),
            _ => r(Risk::Network, "installs packages"),
        },
        "apt" | "apt-get" | "dnf" | "yum" | "pacman" | "zypper" | "apk" | "port" => match sub(args) {
            "list" | "search" | "show" | "info" | "policy" | "" => r(Risk::Read, ""),
            _ => r(Risk::Network, "installs packages"),
        },
        "cargo" => match sub(args) {
            "install" | "add" | "update" | "fetch" | "publish" | "search" | "login" => r(Risk::Network, "uses the network"),
            "--version" | "-V" | "tree" | "metadata" | "help" | "" => r(Risk::Read, ""),
            "clean" => r(Risk::Delete, "deletes build output"),
            _ => r(Risk::Write, "builds the project"),
        },
        "go" => match sub(args) {
            "get" | "install" | "mod" => r(Risk::Network, "uses the network"),
            "version" | "env" | "list" | "doc" | "help" | "" => r(Risk::Read, ""),
            "clean" => r(Risk::Delete, "deletes build output"),
            _ => r(Risk::Write, "builds the project"),
        },
        "docker" | "podman" => match sub(args) {
            "ps" | "images" | "logs" | "inspect" | "version" | "info" | "stats" | "top" | "" => r(Risk::Read, ""),
            "rm" | "rmi" | "prune" | "kill" => r(Risk::Delete, "removes containers"),
            "run" | "build" | "pull" | "push" | "login" | "compose" => r(Risk::Network, "runs containers"),
            _ => r(Risk::Write, "changes containers"),
        },
        "kubectl" => match sub(args) {
            "get" | "describe" | "logs" | "top" | "version" | "explain" | "config" | "" => r(Risk::Network, "uses the cluster"),
            "delete" => r(Risk::Delete, "deletes cluster resources"),
            _ => r(Risk::Network, "changes the cluster"),
        },
        // The read-only forms of system tools; anything else they do changes the system.
        "log" => match sub(args) {
            "show" | "stream" | "stats" | "help" => r(Risk::Read, ""),
            _ => r(Risk::Admin, "changes logging"),
        },
        "diskutil" => match sub(args) {
            "list" | "info" | "information" | "activity" | "listFilesystems" => r(Risk::Read, ""),
            _ => r(Risk::Admin, "changes disks"),
        },
        "launchctl" => match sub(args) {
            "list" | "print" | "print-cache" | "print-disabled" | "blame" | "version" | "help" => r(Risk::Read, ""),
            _ => r(Risk::Admin, "changes services"),
        },
        "systemctl" => match sub(args) {
            "status" | "list-units" | "list-unit-files" | "list-timers" | "list-sockets" | "is-active" | "is-enabled" | "is-failed" | "show"
            | "cat" => r(Risk::Read, ""),
            _ => r(Risk::Admin, "changes services"),
        },
        "tmutil" => match sub(args) {
            "status" | "listbackups" | "latestbackup" | "destinationinfo" | "machinedirectory" | "isexcluded" => r(Risk::Read, ""),
            _ => r(Risk::Admin, "changes backups"),
        },
        "csrutil" if sub(args) == "status" => r(Risk::Read, ""),
        "ipconfig" => match sub(args) {
            "ifcount" => r(Risk::Read, ""),
            name if name.starts_with("get") => r(Risk::Read, ""),
            _ => r(Risk::Admin, "changes the network"),
        },
        "scutil" if args.first().is_some_and(|w| matches!(w.text.as_str(), "--get" | "--dns" | "--proxy" | "--nwi")) => r(Risk::Read, ""),
        "networksetup" if args.first().is_some_and(|w| w.text.starts_with("-get") || w.text.starts_with("-list")) => r(Risk::Read, ""),
        "plutil" if args.first().is_some_and(|w| matches!(w.text.as_str(), "-p" | "-lint")) => r(Risk::Read, ""),
        // `<tool> --version` only prints the version.
        _ if args.len() == 1 && matches!(args[0].text.as_str(), "--version" | "-version") => r(Risk::Read, ""),
        "open" => r(Risk::Write, "opens an app"),
        "make" | "cmake" | "ninja" | "gradle" | "mvn" | "xcodebuild" | "swift" | "rustc" | "gcc" | "cc" | "clang" | "tsc" => {
            r(Risk::Write, "builds the project")
        }
        "pbcopy" => r(Risk::Write, "writes the clipboard"),
        "watch" => {
            // watch <command>: the command it repeats.
            let rest = skip_options(args, &["-n", "-d"]);
            if rest.is_empty() {
                r(Risk::Read, "")
            } else {
                analyze_cmd(rest, &[], false, depth + 1, shell, out, expanded);
                r(Risk::Read, "")
            }
        }
        _ if EDITORS.contains(&name) => r(Risk::Write, "opens an editor"),
        _ if NETWORK.contains(&name) => r(Risk::Network, "uses the network"),
        _ if ADMIN.contains(&name) || name.starts_with("mkfs") => r(Risk::Admin, "changes the system"),
        _ if READ.contains(&name) => r(Risk::Read, ""),
        _ => r(Risk::Write, &format!("runs {name}")),
    }
}

/// Under the folders the system and Homebrew install programs into (after resolving links).
fn system_program(path: &Path) -> bool {
    const BIN: &[&str] = &[
        "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/libexec/", "/usr/local/bin/", "/usr/local/sbin/", "/opt/homebrew/bin/",
        "/opt/homebrew/sbin/", "/opt/homebrew/Cellar/", "/usr/local/Cellar/", "/Library/Apple/usr/bin/", "/System/",
    ];
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let text = real.to_string_lossy();
    BIN.iter().any(|dir| text.starts_with(dir))
}

/// A skills plugin's script in the live folder (`<home>/live/plugins/skills-<id>/data/scripts/<name>`)
/// run with a subcommand its plugin's `data/scripts/readonly` lists for it: one line per script,
/// its name, then the subcommands that only read. None: not such a script, judged like any other program.
fn skills_script(path: &Path, args: &[Word]) -> Option<(Risk, String)> {
    // In safe mode the frame withholds the live folder (its files are the person's to edit): no
    // script there is trusted as read-only.
    std::env::var_os("CORTEX_PLUGIN_LIVE").filter(|v| !v.is_empty())?;
    let plugins = crate::wire::home().join("live").join("plugins").canonicalize().ok()?;
    let path = path.canonicalize().ok()?;
    let parts: Vec<&str> = path.strip_prefix(&plugins).ok()?.iter().map(|part| part.to_str()).collect::<Option<_>>()?;
    let [plugin, "data", "scripts", script] = parts[..] else { return None };
    let id = plugin.strip_prefix("skills-")?;
    let listed = std::fs::read_to_string(plugins.join(plugin).join("data").join("scripts").join("readonly")).ok()?;
    let line = listed.lines().map(|line| line.split_whitespace().collect::<Vec<_>>()).find(|words| words.first() == Some(&script))?;
    let subcommand = args.first().filter(|word| !word.dynamic())?;
    if !line[1..].contains(&subcommand.text.as_str()) {
        return None;
    }
    Some((Risk::Read, format!("a read-only check from the {id} skills")))
}

fn git(args: &[Word]) -> (Risk, String, bool) {
    let r = |risk: Risk, reason: &str| (risk, reason.to_owned(), false);
    let files = |risk: Risk, reason: &str| (risk, reason.to_owned(), true);
    // Global options before the subcommand.
    let mut i = 0;
    while i < args.len() && args[i].text.starts_with('-') {
        match args[i].text.as_str() {
            "-c" => return r(Risk::Unknown, "git -c"),
            "-C" | "--git-dir" | "--work-tree" | "--namespace" => i += 2,
            _ => i += 1,
        }
    }
    let Some(subcommand) = args.get(i) else { return r(Risk::Read, "") };
    let rest = &args[i + 1..];
    let positional = rest.iter().filter(|w| !w.text.starts_with('-')).count();
    match subcommand.text.as_str() {
        "status" | "log" | "diff" | "show" | "blame" | "shortlog" | "describe" | "rev-parse" | "rev-list" | "ls-files"
        | "ls-tree" | "grep" | "reflog" | "cat-file" | "whatchanged" | "help" | "version" | "show-ref" | "for-each-ref"
        | "merge-base" | "name-rev" | "count-objects" | "check-ignore" => r(Risk::Read, ""),
        "fetch" | "pull" | "push" | "clone" | "ls-remote" | "submodule" => r(Risk::Network, "uses the network"),
        "clean" => r(Risk::Delete, "deletes untracked files"),
        "rm" => files(Risk::Delete, "deletes files"),
        "reset" if has(rest, "--hard") => r(Risk::Delete, "discards changes"),
        "checkout" | "restore" if rest.iter().any(|w| w.text == "--" || w.text == ".") => r(Risk::Delete, "discards changes"),
        "branch" => {
            if short_flag(rest, 'd') || short_flag(rest, 'D') || has(rest, "--delete") {
                r(Risk::Delete, "deletes branches")
            } else if positional == 0 || has(rest, "--list") || has(rest, "--show-current") {
                r(Risk::Read, "")
            } else {
                r(Risk::Write, "changes branches")
            }
        }
        "tag" => {
            if short_flag(rest, 'd') || has(rest, "--delete") {
                r(Risk::Delete, "deletes tags")
            } else if positional == 0 || short_flag(rest, 'l') || has(rest, "--list") {
                r(Risk::Read, "")
            } else {
                r(Risk::Write, "creates a tag")
            }
        }
        "remote" => match rest.iter().find(|w| !w.text.starts_with('-')).map(|w| w.text.as_str()) {
            None | Some("show" | "get-url") => r(Risk::Read, ""),
            _ => r(Risk::Write, "changes remotes"),
        },
        "stash" => match rest.first().map(|w| w.text.as_str()) {
            Some("list" | "show") => r(Risk::Read, ""),
            Some("drop" | "clear") => r(Risk::Delete, "deletes stashes"),
            _ => r(Risk::Write, "changes the working tree"),
        },
        "worktree" => match rest.first().map(|w| w.text.as_str()) {
            Some("list") => r(Risk::Read, ""),
            Some("remove" | "prune") => r(Risk::Delete, "deletes worktrees"),
            _ => r(Risk::Write, "changes worktrees"),
        },
        "config" => {
            if positional <= 1 || ["--get", "--get-all", "--list", "-l", "--get-regexp"].iter().any(|f| has(rest, f)) {
                r(Risk::Read, "")
            } else {
                r(Risk::Write, "changes git settings")
            }
        }
        "add" | "mv" => files(Risk::Write, "changes the repository"),
        _ => r(Risk::Write, "changes the repository"),
    }
}

// ---------------------------------------------------------------------------------------------
// Matches

fn matches(targets: &[Word], cwd: &Path) -> Option<GlobMatches> {
    let started = Instant::now();
    let mut found = GlobMatches::default();
    let mut entries = 0usize;
    let mut seen = std::collections::HashSet::new();
    let mut add = |path: PathBuf, found: &mut GlobMatches, entries: &mut usize| {
        if !seen.insert(path.clone()) {
            return;
        }
        let Ok(meta) = std::fs::symlink_metadata(&path) else { return };
        if found.sample.len() < 5 {
            let shown = path.strip_prefix(cwd).ok().filter(|p| !p.as_os_str().is_empty()).map_or_else(
                || path.to_string_lossy().into_owned(),
                |p| p.to_string_lossy().into_owned(),
            );
            found.sample.push(if meta.is_dir() && !shown.ends_with('/') { format!("{shown}/") } else { shown });
        }
        if meta.is_dir() {
            found.dirs += 1;
            walk(&path, found, entries, started);
        } else {
            found.files += 1;
            found.bytes += meta.len();
        }
    };
    for word in targets {
        if word.dynamic() || started.elapsed() > WALK_TIME {
            continue;
        }
        if word.glob {
            let pattern = expand(&word.text, cwd);
            let base = glob::Pattern::escape(&cwd.to_string_lossy());
            let pattern = pattern.to_string_lossy().replacen(&cwd.to_string_lossy().into_owned(), &base, 1);
            let options = glob::MatchOptions { require_literal_leading_dot: true, ..glob::MatchOptions::new() };
            if let Ok(paths) = glob::glob_with(&pattern, options) {
                for path in paths.flatten().take(WALK_ENTRIES) {
                    add(path, &mut found, &mut entries);
                }
            }
        } else {
            let path = expand(&word.text, cwd);
            if std::fs::symlink_metadata(&path).is_ok() {
                add(path, &mut found, &mut entries);
            }
        }
    }
    (found.files + found.dirs > 0).then_some(found)
}

fn walk(dir: &Path, found: &mut GlobMatches, entries: &mut usize, started: Instant) {
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        let Ok(read) = std::fs::read_dir(&current) else { continue };
        for entry in read.flatten() {
            *entries += 1;
            if *entries > WALK_ENTRIES || started.elapsed() > WALK_TIME {
                return;
            }
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                found.dirs += 1;
                stack.push(entry.path());
            } else {
                found.files += 1;
                found.bytes += meta.len();
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Kind

const STOP_WORDS: &[&str] = &[
    "the", "a", "an", "my", "me", "i", "how", "what", "why", "where", "when", "which", "who", "please", "can", "could",
    "would", "should", "is", "are", "was", "do", "does", "did", "to", "of", "for", "in", "on", "all", "that", "this", "these",
    "those", "with", "from", "and", "it", "its", "there", "any", "some", "you", "your", "about", "into", "than", "explain",
];

const QUESTION_WORDS: &[&str] = &["how", "what", "what's", "whats", "why", "where", "when", "which", "who", "can", "could", "should", "is", "are", "does", "do", "please", "explain"];

/// Words outside quotes, lowercased, without punctuation around them.
fn plain_words(text: &str) -> Vec<String> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    for c in text.chars() {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => {}
            None if (c == '"' || c == '\'') && current.is_empty() => {
                quote = Some(c);
                words.push("\"\"".to_owned());
            }
            None if c.is_whitespace() => {
                if !current.is_empty() {
                    words.push(std::mem::take(&mut current));
                }
            }
            None => current.push(c),
        }
    }
    if !current.is_empty() {
        words.push(current);
    }
    words
}

fn kind(text: &str, shell: &Shell) -> &'static str {
    let words = plain_words(text);
    let Some(first) = words.first() else { return "shell" };
    let first_resolves = first.contains('=') || shell.resolve(first).is_some();
    let strong = text.contains(['|', '>', '<', ';', '`'])
        || text.contains("&&")
        || text.contains("$(")
        || text.contains('$')
        || words.iter().skip(1).any(|w| w.starts_with('-') && w.len() > 1)
        || words.iter().any(|w| is_assignment(&Word { text: w.clone(), ..Word::default() }));
    let weak = words.iter().any(|w| w.contains('/') || w.starts_with('~') || w.contains('*'));
    let lower: Vec<String> = words.iter().map(|w| w.trim_matches(|c: char| !c.is_alphanumeric() && c != '\'').to_lowercase()).collect();
    let stops = lower.iter().filter(|w| STOP_WORDS.contains(&w.as_str())).count();
    let question = text.trim_end().ends_with('?');
    let n = words.len();
    let sentence = (question && n >= 2)
        || (n >= 4 && stops >= 1)
        || (n >= 3 && QUESTION_WORDS.contains(&lower[0].as_str()));
    match (first_resolves, strong, sentence) {
        (true, true, _) => "shell",
        // A sentence that starts with a program's name (`which node do I have?`, `find the big
        // files in my folder`) is a question: the assistant runs the read-only checks itself.
        (true, false, true) if (question && n >= 3) || stops >= 2 => "ask",
        (true, false, true) => "unsure",
        (true, false, false) => "shell",
        (false, _, true) => "ask",
        (false, true, false) => "shell",
        (false, false, false) if weak => "shell",
        // One word that is not a program here is still a command (`htop` not installed): the
        // shell says so, and a native view may stand in for it.
        (false, false, false) if n == 1 => "shell",
        (false, false, false) if n >= 3 => "ask",
        _ => "unsure",
    }
}

/// Assess typed (or `pasted`) input for a terminal in `cwd`.
pub fn assess(input: &str, shell: &Shell, pasted: bool) -> Assessment {
    let trimmed = input.trim();
    let (forced, text) = if let Some(rest) = trimmed.strip_prefix('?') {
        (Some("ask"), rest.trim_start())
    } else if let Some(rest) = trimmed.strip_prefix('!') {
        (Some("shell"), rest.trim_start())
    } else {
        (None, trimmed)
    };
    let kind = forced.unwrap_or_else(|| kind(text, shell));
    let mut assessment =
        Assessment { kind: kind.into(), text: text.into(), cwd: shell.cwd.to_string_lossy().into_owned(), risk: "read".into(), ..Assessment::default() };
    if kind == "ask" {
        return assessment;
    }
    let mut out = Analysis::default();
    analyze_script(text, 0, shell, &mut out);
    // What the paste guard finds is never safe: at least unknown, so it is asked first.
    assessment.threats = threat::scan(text, pasted);
    if !assessment.threats.is_empty() {
        out.add(Risk::Unknown, "");
    }
    let risk = out.risk.unwrap_or(Risk::Read);
    assessment.risk = risk.name().into();
    assessment.safe = risk == Risk::Read;
    assessment.reasons = out.reasons;
    assessment.program = out.program;
    if matches!(risk, Risk::Write | Risk::Delete | Risk::Admin | Risk::Unknown | Risk::Network) && !out.targets.is_empty() {
        assessment.matches = matches(&out.targets, shell.cwd);
    }
    assessment
}

//! Curated static option/value knowledge. No help process, generator, version probe or network
//! call. The user's installed version is not inferred from this reference; unknown forms fall back.
//! Reference URLs and scope are recorded in docs/weekly-ideas-implementation/2026-11-21/README.md.

use crate::assess::Shell;
use crate::shell_text::{self, Token};
use cc_protocol::contracts::terminal::{Completion, Completions};
use std::collections::HashSet;

#[derive(Clone, Copy)]
enum Arg { None, Text, File, Dir, Choices(&'static [&'static str]) }
struct Flag { names: &'static [&'static str], help: &'static str, arg: Arg }
const fn flag(names: &'static [&'static str], help: &'static str, arg: Arg) -> Flag { Flag { names, help, arg } }
struct Spec { path: &'static str, flags: &'static [Flag] }
const SPECS: &[Spec] = &[
    Spec { path: "git", flags: &[
        flag(&["--version"], "Show Git's version", Arg::None),
        flag(&["--no-pager"], "Write output without a pager", Arg::None),
        flag(&["-C"], "Use this working directory", Arg::Dir),
        flag(&["-c"], "Set one configuration value", Arg::Text),
        flag(&["--git-dir"], "Use this repository metadata directory", Arg::Dir),
        flag(&["--work-tree"], "Use this working tree", Arg::Dir),
    ] },
    Spec { path: "git log", flags: &[
        flag(&["--since", "--after"], "Show commits newer than this date", Arg::Text),
        flag(&["--until", "--before"], "Show commits older than this date", Arg::Text),
        flag(&["--author"], "Filter by author pattern", Arg::Text),
        flag(&["--grep"], "Filter commit messages", Arg::Text),
        flag(&["--max-count", "-n"], "Limit the number of commits", Arg::Text),
        flag(&["--oneline"], "Show one line per commit", Arg::None),
        flag(&["--graph"], "Draw commit relationships", Arg::None),
        flag(&["--all"], "Include all references", Arg::None),
        flag(&["--stat"], "Summarize changed files", Arg::None),
        flag(&["--patch", "-p"], "Show each commit's changes", Arg::None),
        flag(&["--decorate"], "Choose reference-name detail", Arg::Choices(&["short", "full", "auto", "no"])),
        flag(&["--date"], "Choose the date display format", Arg::Choices(&["relative", "local", "iso", "iso-strict", "short", "unix", "default"])),
        flag(&["--format"], "Use this output format", Arg::Text),
    ] },
    Spec { path: "git status", flags: &[
        flag(&["--short", "-s"], "Use the short status format", Arg::None),
        flag(&["--branch", "-b"], "Include branch information", Arg::None),
        flag(&["--porcelain"], "Choose a stable output format", Arg::Choices(&["v1", "v2"])),
        flag(&["--untracked-files", "-u"], "Choose which untracked files to show", Arg::Choices(&["no", "normal", "all"])),
        flag(&["--ignored"], "Show ignored files", Arg::None),
    ] },
    Spec { path: "git diff", flags: &[
        flag(&["--cached", "--staged"], "Compare staged changes", Arg::None),
        flag(&["--stat"], "Summarize changed files", Arg::None),
        flag(&["--name-only"], "Show changed paths", Arg::None),
        flag(&["--name-status"], "Show paths and change types", Arg::None),
        flag(&["--check"], "Report whitespace errors", Arg::None),
        flag(&["--word-diff"], "Choose word-level change display", Arg::Choices(&["color", "plain", "porcelain", "none"])),
        flag(&["--diff-algorithm"], "Choose how matching lines are found", Arg::Choices(&["myers", "minimal", "patience", "histogram"])),
    ] },
    Spec { path: "kubectl", flags: &[
        flag(&["--namespace", "-n"], "Use this namespace", Arg::Text),
        flag(&["--context"], "Use this configuration context", Arg::Text),
        flag(&["--kubeconfig"], "Use this configuration file", Arg::File),
        flag(&["--request-timeout"], "Limit a server request's duration", Arg::Text),
    ] },
    Spec { path: "kubectl logs", flags: &[
        flag(&["--since"], "Show logs from a recent duration, such as 1h", Arg::Text),
        flag(&["--since-time"], "Show logs after this timestamp", Arg::Text),
        flag(&["--container", "-c"], "Choose a container", Arg::Text),
        flag(&["--follow", "-f"], "Stream new log output", Arg::None),
        flag(&["--previous", "-p"], "Read the previous container instance", Arg::None),
        flag(&["--tail"], "Limit the number of recent lines", Arg::Text),
        flag(&["--timestamps"], "Include timestamps", Arg::None),
        flag(&["--all-containers"], "Include every container in the selected pods", Arg::None),
        flag(&["--prefix"], "Label each line with its pod and container", Arg::None),
    ] },
    Spec { path: "kubectl get", flags: &[
        flag(&["--output", "-o"], "Choose the result format", Arg::Choices(&["json", "yaml", "wide", "name"])),
        flag(&["--watch", "-w"], "Watch for changes", Arg::None),
        flag(&["--all-namespaces", "-A"], "Include every namespace", Arg::None),
        flag(&["--selector", "-l"], "Select by label expression", Arg::Text),
        flag(&["--field-selector"], "Select by field expression", Arg::Text),
        flag(&["--sort-by"], "Sort by this field", Arg::Text),
        flag(&["--no-headers"], "Omit table headers", Arg::None),
        flag(&["--show-labels"], "Include resource labels", Arg::None),
    ] },
    Spec { path: "docker", flags: &[
        flag(&["--context", "-c"], "Use this Docker context", Arg::Text),
        flag(&["--host", "-H"], "Use this daemon endpoint", Arg::Text),
        flag(&["--config"], "Use this client configuration directory", Arg::Dir),
        flag(&["--version", "-v"], "Show Docker's version", Arg::None),
    ] },
    Spec { path: "docker container", flags: &[
    ] },
    Spec { path: "docker logs", flags: &[
        flag(&["--follow", "-f"], "Stream new log output", Arg::None),
        flag(&["--since"], "Show logs after this time or duration", Arg::Text),
        flag(&["--until"], "Stop at this time or duration", Arg::Text),
        flag(&["--tail", "-n"], "Limit the number of recent lines", Arg::Text),
        flag(&["--timestamps", "-t"], "Include timestamps", Arg::None),
        flag(&["--details"], "Include extra log details", Arg::None),
    ] },
    Spec { path: "docker ps", flags: &[
        flag(&["--all", "-a"], "Include stopped containers", Arg::None),
        flag(&["--quiet", "-q"], "Show only container identifiers", Arg::None),
        flag(&["--filter", "-f"], "Filter containers by condition", Arg::Text),
        flag(&["--format"], "Use a Go-template format, or json", Arg::Text),
        flag(&["--no-trunc"], "Show full identifiers and command text", Arg::None),
        flag(&["--size", "-s"], "Show filesystem sizes", Arg::None),
    ] },
    Spec { path: "curl", flags: &[
        flag(&["--head", "-I"], "Request response headers only", Arg::None),
        flag(&["--include", "-i"], "Include headers with the response", Arg::None),
        flag(&["--location", "-L"], "Follow redirects", Arg::None),
        flag(&["--fail", "-f"], "Fail on HTTP error responses", Arg::None),
        flag(&["--silent", "-s"], "Hide progress and error output", Arg::None),
        flag(&["--show-error", "-S"], "Show errors even with silent mode", Arg::None),
        flag(&["--output", "-o"], "Write the response to this file", Arg::File),
        flag(&["--dump-header", "-D"], "Write response headers to this file", Arg::File),
        flag(&["--request", "-X"], "Choose the HTTP method", Arg::Choices(&["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"])),
        flag(&["--header", "-H"], "Add a request header", Arg::Text),
        flag(&["--data", "-d"], "Send this request data", Arg::Text),
        flag(&["--max-time", "-m"], "Limit total transfer time in seconds", Arg::Text),
        flag(&["--connect-timeout"], "Limit connection time in seconds", Arg::Text),
        flag(&["--retry"], "Set retry attempts", Arg::Text),
        flag(&["--version", "-V"], "Show curl's version", Arg::None),
    ] },
    Spec { path: "npm", flags: &[
        flag(&["--version", "-v"], "Show npm's version", Arg::None),
        flag(&["--loglevel"], "Choose logging detail", Arg::Choices(&["silent", "error", "warn", "notice", "http", "info", "verbose", "silly"])),
        flag(&["--prefix"], "Use this package directory", Arg::Dir),
    ] },
    Spec { path: "npm run", flags: &[
        flag(&["--if-present"], "Do not fail when the script is absent", Arg::None),
        flag(&["--ignore-scripts"], "Skip pre/post lifecycle scripts", Arg::None),
        flag(&["--workspace", "-w"], "Choose a workspace", Arg::Text),
        flag(&["--workspaces"], "Use all workspaces", Arg::None),
    ] },
    Spec { path: "npm install", flags: &[
        flag(&["--save-dev", "-D"], "Save as a development dependency", Arg::None),
        flag(&["--save-exact", "-E"], "Save an exact version", Arg::None),
        flag(&["--ignore-scripts"], "Do not run package lifecycle scripts", Arg::None),
        flag(&["--dry-run"], "Describe changes without installing", Arg::None),
        flag(&["--package-lock-only"], "Update only the lockfile", Arg::None),
        flag(&["--omit"], "Omit this dependency group from disk", Arg::Choices(&["dev", "optional", "peer"])),
    ] },
];

const HELP: Flag = flag(&["--help"], "Show command help", Arg::None);

fn spec(path: &str) -> Option<&'static Spec> {
    let canonical = match path {
        "docker container logs" => "docker logs",
        "docker container ls" => "docker ps",
        _ => path,
    };
    SPECS.iter().find(|s| s.path == canonical)
}

fn flags(path: &str) -> Vec<&'static Flag> {
    let mut out: Vec<_> = spec(path).into_iter().flat_map(|s| s.flags).collect();
    if path.starts_with("kubectl ") {
        out.extend(spec("kubectl").unwrap().flags);
    }
    out.push(&HELP);
    out
}

fn optional(flag: &Flag) -> bool {
    matches!(flag.names[0], "--decorate" | "--porcelain" | "--untracked-files" | "--word-diff")
}

fn values(arg: Arg, prefix: &str, from: usize, to: usize, shell: &Shell<'_>, suggestion: Option<String>) -> Completions {
    let items = match arg {
        Arg::Choices(values) => values.iter().filter(|v| v.starts_with(prefix)).map(|v| Completion {
            value: (*v).into(), kind: "flag".into(), description: "Static option value".into(),
        }).collect(),
        Arg::File | Arg::Dir => crate::complete::files(prefix, shell.cwd, matches!(arg, Arg::Dir)),
        _ => Vec::new(),
    };
    Completions { from: from as u32, to: Some(to as u32), items, suggestion }
}

/// Only handles known options/values. Ordinary program/path/branch completion stays with the
/// existing provider. A registry miss never rejects or rewrites a command.
pub(crate) fn complete(line: &str, cursor: usize, shell: &Shell<'_>, suggestion: Option<String>) -> Option<Completions> {
    if line.len() > 16 * 1024 { return None; }
    let prefix = shell_text::scan(&line[..cursor]);
    if prefix.error.is_some() { return None; }
    let mut prior = Vec::new();
    let mut current = "";
    let mut from = cursor;
    let last = prefix.tokens.len().saturating_sub(1);
    for (index, token) in prefix.tokens.iter().enumerate() {
        match token {
            Token::Op(";" | "\n" | "|" | "||" | "&&" | "&", _) => prior.clear(),
            Token::Op(_, _) => return None,
            Token::Word(word) if index == last && word.end == cursor => {
                current = word.raw;
                from = word.start;
            }
            Token::Word(word) => prior.push(word.literal()?),
        }
    }
    if prior.is_empty() || current.contains(['$', '`', '\'', '"', '\\']) { return None; }
    // A command at the cursor is still a command-name completion, not an option context.
    let whole = shell_text::scan(line);
    let to = whole.tokens.iter().find_map(|token| match token {
        Token::Word(w) if w.start == from && w.end >= cursor => Some(w.end),
        _ => None,
    }).unwrap_or(cursor);
    let mut alias_names = HashSet::new();
    for _ in 0..8 {
        let name = prior.first()?.clone();
        if shell.env.functions.contains(&name) { return None; }
        let Some(alias) = shell.env.aliases.get(&name) else { break; };
        if !alias_names.insert(name.clone()) { return None; }
        let parsed = shell_text::scan(alias);
        if parsed.error.is_some() { return None; }
        let mut expanded = Vec::new();
        for token in &parsed.tokens {
            match token { Token::Word(w) => expanded.push(w.literal()?), _ => return None }
        }
        if expanded.is_empty() { return None; }
        expanded.extend(prior.drain(1..));
        prior = expanded;
        // A self-named alias is expanded once, just as in the shell.
        if prior.first() == Some(&name) { break; }
    }
    // Explicitly supported wrappers only. Unknown wrapper flags cannot consume a guessed value.
    loop {
        let name = prior.first()?.as_str();
        if name.split_once('=').is_some_and(|(key, _)| !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')) {
            prior.remove(0); continue;
        }
        if matches!(name, "command" | "builtin" | "exec" | "nohup") {
            prior.remove(0);
            if prior.first().is_some_and(|w| w.starts_with('-')) { return None; }
            continue;
        }
        if !matches!(name, "sudo" | "doas" | "env") { break; }
        let wrapper = prior.remove(0);
        while let Some(option) = prior.first() {
            if option == "--" { prior.remove(0); break; }
            if !option.starts_with('-') { break; }
            if wrapper == "env" { return None; }
            if matches!(option.as_str(), "-u" | "-g") && prior.len() > 1 { prior.drain(..2); }
            else if matches!(option.as_str(), "-E" | "-H" | "-n") { prior.remove(0); }
            else { return None; }
        }
    }
    let first = prior.first()?;
    if shell.env.functions.contains(first) { return None; }
    let mut path = first.rsplit('/').next()?.to_owned();
    spec(&path)?;
    let mut used = HashSet::new();
    let mut expected = None;
    let mut positional = false;
    for word in &prior[1..] {
        if positional { continue; }
        if expected.take().is_some() { continue; }
        if word == "--" {
            positional = true;
            continue;
        }
        if word.starts_with('-') {
            let (name, inline) = word.split_once('=').map_or((word.as_str(), false), |(name, _)| (name, true));
            let available = flags(&path);
            let found = available.iter().copied().find(|f| f.names.contains(&name));
            let found = if let Some(found) = found { found }
                else if !word.starts_with("--") && word.len() > 2 && word.is_ascii() {
                    for index in 1..word.len() {
                        let short = format!("-{}", &word[index..index + 1]);
                        let flag = available.iter().copied().find(|f| f.names.contains(&short.as_str()))?;
                        used.insert(flag.names[0]);
                        if !matches!(flag.arg, Arg::None) {
                            if index + 1 == word.len() && !optional(flag) { expected = Some(flag.arg); }
                            break;
                        }
                    }
                    continue;
                } else { return None };
            used.insert(found.names[0]);
            if !inline && !matches!(found.arg, Arg::None) && !optional(found) { expected = Some(found.arg); }
        } else {
            let child = format!("{path} {word}");
            if spec(&child).is_some() { path = child; }
            else if matches!(path.as_str(), "git" | "kubectl" | "docker" | "docker container" | "npm") { return None; }
        }
    }
    if positional {
        // npm forwards these words to a script whose interface we do not know.
        return if path == "npm run" { Some(values(Arg::Text, current, from, to, shell, suggestion)) }
            else { Some(values(Arg::File, current, from, to, shell, suggestion)) };
    }
    if let Some(arg) = expected { return Some(values(arg, current, from, to, shell, suggestion)); }
    if let Some((name, value)) = current.split_once('=') {
        let flag = flags(&path).into_iter().find(|f| f.names.contains(&name))?;
        return Some(values(flag.arg, value, from + name.len() + 1, to, shell, suggestion));
    }
    if current.starts_with('-') && !current.starts_with("--") && current.len() > 2 && current.is_ascii() {
        let available = flags(&path);
        for index in 1..current.len() {
            let short = format!("-{}", &current[index..index + 1]);
            let Some(flag) = available.iter().copied().find(|f| f.names.contains(&short.as_str())) else { break; };
            if !matches!(flag.arg, Arg::None) {
                return Some(values(flag.arg, &current[index + 1..], from + index + 1, to, shell, suggestion));
            }
        }
    }
    if !current.starts_with('-') { return None; }
    let mut items = Vec::new();
    for flag in flags(&path) {
        if used.contains(flag.names[0]) { continue; }
        if path == "kubectl logs" && (flag.names[0] == "--since" && used.contains("--since-time") || flag.names[0] == "--since-time" && used.contains("--since")) { continue; }
        for name in flag.names.iter().filter(|name| name.starts_with(current)) {
            let value = if name.starts_with("--") && matches!(flag.arg, Arg::Choices(_)) { format!("{name}=") } else { (*name).to_owned() };
            items.push(Completion { value, kind: "flag".into(), description: flag.help.into() });
        }
    }
    items.sort_by(|a, b| a.value.cmp(&b.value));
    Some(Completions { from: from as u32, to: Some(to as u32), items, suggestion })
}

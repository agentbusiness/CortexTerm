//! The explicit `edit` command: a literal file path and a folder picker, without shell execution.

use crate::assess::expand;
use cc_protocol::contracts::terminal::{Completion, Completions};
use cc_protocol::{RpcError, codes};
use std::path::Path;

/// Only a standalone, single-line `edit` enters the app. `!edit`, wrappers and other tools do not.
pub fn query(line: &str) -> Option<&str> {
    if line.contains(['\n', '\r', '\0']) {
        return None;
    }
    let rest = line.trim_start_matches([' ', '\t']).strip_prefix("edit")?;
    if !rest.is_empty() && !rest.starts_with([' ', '\t']) {
        return None;
    }
    Some(rest.trim_start_matches([' ', '\t']))
}

/// Accept quoted/backslash-escaped paths, including unfinished quotes while finding a file.
/// Spaces remain part of the path; variables, globs and command substitutions are never evaluated.
pub fn path(query: &str) -> String {
    let mut path = String::new();
    let mut quote = None;
    let mut chars = query.trim_start_matches([' ', '\t']).chars();
    while let Some(c) = chars.next() {
        match c {
            '\\' if quote != Some('\'') => path.push(chars.next().unwrap_or('\\')),
            '\'' | '"' if quote == Some(c) => quote = None,
            '\'' | '"' if quote.is_none() => quote = Some(c),
            _ => path.push(c),
        }
    }
    path
}

fn escaped(path: &str) -> String {
    match path.strip_prefix("~/") {
        Some(rest) => format!("~/{}", crate::complete::escape(rest)),
        None => crate::complete::escape(path),
    }
}

fn match_rank(name: &str, query: &str) -> Option<u8> {
    if name == query { return Some(0); }
    if name.starts_with(query) { return Some(1); }
    let (name, query) = (name.to_lowercase(), query.to_lowercase());
    if name == query { return Some(2); }
    if name.starts_with(&query) { return Some(3); }
    if name.contains(&query) { return Some(4); }
    let mut chars = name.chars();
    query.chars().all(|wanted| chars.by_ref().any(|c| c == wanted)).then_some(5)
}

pub fn complete(line: &str, cwd: &Path) -> Result<Completions, RpcError> {
    let query = query(line).ok_or_else(|| RpcError::invalid_params("expected edit and a file path"))?;
    let typed = path(query);
    let typed = if typed == "~" { "~/".to_owned() } else { typed };
    let (folder, prefix) = typed.rsplit_once('/').map_or(("", typed.as_str()), |(dir, name)| (&typed[..dir.len() + 1], name));
    let dir = expand(folder, cwd);
    let entries = std::fs::read_dir(&dir).map_err(|error| RpcError::new(codes::NOT_FOUND, format!("Cannot read {}: {error}", dir.display())))?;
    let mut found = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') && !prefix.starts_with('.') { continue; }
        if name.chars().any(char::is_control) { continue; }
        let Some(rank) = match_rank(&name, prefix) else { continue };
        let Ok(meta) = std::fs::metadata(entry.path()) else { continue };
        if !meta.is_dir() && !meta.is_file() { continue; }
        let is_dir = meta.is_dir();
        let shown = format!("{folder}{name}{}", if is_dir { "/" } else { "" });
        let item = Completion { value: escaped(&shown), kind: if is_dir { "dir" } else { "file" }.into(), description: shown };
        found.push((rank, !is_dir, name.to_lowercase(), item));
    }
    found.sort_by(|a, b| (&a.0, &a.1, &a.2, &a.3.value).cmp(&(&b.0, &b.1, &b.2, &b.3.value)));
    let create = !prefix.is_empty() && !expand(&typed, cwd).exists();
    let parent = prefix.is_empty() && dir.parent().is_some();
    found.truncate(12 - usize::from(create) - usize::from(parent));
    let mut items: Vec<Completion> = found.into_iter().map(|(_, _, _, item)| item).collect();
    if parent {
        items.insert(0, Completion { value: escaped(&format!("{folder}../")), kind: "dir".into(), description: ".. / Parent folder".into() });
    }
    if create {
        items.push(Completion { value: escaped(&typed), kind: "new".into(), description: format!("Create {typed}") });
    }
    Ok(Completions { from: (line.len() - query.len()) as u32, items, suggestion: None })
}

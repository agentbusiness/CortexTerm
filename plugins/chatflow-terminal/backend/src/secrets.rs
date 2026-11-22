//! Secrets are masked before a model reads them: every message of a `model.chat` call this flow
//! makes (command and service output, recorded Runs, a terminal episode for the learner) has each
//! secret-shaped match replaced by `[secret masked: <label>]`. What the model writes back (answers,
//! lessons kept in the graph) therefore never holds one. The person's own view and the session
//! journal keep the text as it came.

use cc_protocol::contracts::model::ChatMessage;
use regex::Regex;
use std::sync::OnceLock;

/// (label, pattern). A match is the secret together with what names it (`password = "…"`); the
/// whole match is masked. Labels are nouns a model can read (`GitHub token`).
const PATTERNS: &[(&str, &str)] = &[
    ("private key", r"(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(?:-----END [A-Z ]*PRIVATE KEY-----|\z)"),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{40,})"),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}"),
    ("AWS access key", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ("Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    ("Stripe key", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}"),
    ("API key", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{20,}"),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}"),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}"),
    ("web token", r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    ("bearer token", r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}=*"),
    ("password in a URL", r"://[^/\s:@]+:[^/\s@]+@"),
    (
        "password or token",
        r#"(?i)\b[A-Z0-9_.-]*(?:password|passwd|secret|token|api_?key|access_?key|private_?key|credential)s?[A-Z0-9_.-]*["']?\s*[:=]\s*["']?[^\s"',;]{6,}"#,
    ),
];

fn compiled() -> &'static [(&'static str, Regex)] {
    static ALL: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    ALL.get_or_init(|| PATTERNS.iter().filter_map(|(label, pattern)| Regex::new(pattern).ok().map(|regex| (*label, regex))).collect())
}

/// The text with every secret-shaped match replaced by `[secret masked: <label>]`.
pub fn mask(text: &str) -> String {
    let mut out = text.to_owned();
    for (label, regex) in compiled() {
        if regex.is_match(&out) {
            // A URL keeps its shape: `https://[secret masked: …]@host`.
            let with = if label.contains("URL") { format!("://[secret masked: {label}]@") } else { format!("[secret masked: {label}]") };
            out = regex.replace_all(&out, regex::NoExpand(&with)).into_owned();
        }
    }
    out
}

/// Mask what a model will read of these messages.
pub fn mask_messages(messages: &mut [ChatMessage]) {
    for message in messages {
        if compiled().iter().any(|(_, regex)| regex.is_match(&message.content)) {
            message.content = mask(&message.content);
        }
    }
}

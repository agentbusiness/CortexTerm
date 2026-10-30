//! What a Run's output looks like: its format (json, logfmt, log, raw) from the first lines, and
//! the level of each line (error, warn, info, debug, or none).

use serde_json::Value;

/// How many lines the format is detected from.
pub const SAMPLE_LINES: usize = 50;

/// `json` when at least 80% of the non-empty lines are JSON objects, `logfmt` when most carry
/// three or more `key=value` pairs, `log` when most have a level word or start with a timestamp,
/// else `raw`.
pub fn detect(lines: &[String]) -> &'static str {
    let lines: Vec<&str> = lines.iter().map(|line| line.trim()).filter(|line| !line.is_empty()).collect();
    if lines.is_empty() {
        return "raw";
    }
    let share = |test: &dyn Fn(&str) -> bool| lines.iter().filter(|line| test(line)).count() * 100 / lines.len();
    if share(&|line| json_object(line).is_some()) >= 80 {
        "json"
    } else if share(&|line| logfmt_pairs(line) >= 3) >= 80 {
        "logfmt"
    } else if share(&|line| !level(line).is_empty() || starts_with_timestamp(line)) >= 50 {
        "log"
    } else {
        "raw"
    }
}

fn json_object(line: &str) -> Option<serde_json::Map<String, Value>> {
    if !line.starts_with('{') {
        return None;
    }
    match serde_json::from_str::<Value>(line) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

fn logfmt_pairs(line: &str) -> usize {
    line.split_whitespace()
        .filter(|word| {
            word.split_once('=').is_some_and(|(key, _)| {
                key.chars().next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && key.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
            })
        })
        .count()
}

/// The level a line reports: a JSON `level`-like field, a logfmt `level=`, or a level word.
pub fn level(line: &str) -> &'static str {
    let trimmed = line.trim();
    if let Some(map) = json_object(trimmed) {
        for key in ["level", "lvl", "severity", "levelname", "log.level", "loglevel", "@l"] {
            match map.get(key) {
                Some(Value::String(name)) => return normalize(name),
                Some(Value::Number(n)) => {
                    // Bunyan and pino: 10 trace, 20 debug, 30 info, 40 warn, 50 error, 60 fatal.
                    return match n.as_u64().unwrap_or(0) {
                        0..=29 => "debug",
                        30..=39 => "info",
                        40..=49 => "warn",
                        _ => "error",
                    };
                }
                _ => {}
            }
        }
        return if map.get("error").or_else(|| map.get("err")).is_some_and(|v| !v.is_null()) { "error" } else { "" };
    }
    for word in trimmed.split_whitespace() {
        if let Some((key, value)) = word.split_once('=')
            && matches!(key.to_ascii_lowercase().as_str(), "level" | "lvl" | "severity")
        {
            let found = normalize(value.trim_matches(|c| c == '"' || c == '\''));
            if !found.is_empty() {
                return found;
            }
        }
    }
    words(trimmed)
}

fn normalize(name: &str) -> &'static str {
    match name.to_ascii_lowercase().as_str() {
        "error" | "err" | "fatal" | "critical" | "crit" | "panic" | "emerg" | "emergency" | "alert" | "e" | "f" => "error",
        "warn" | "warning" | "w" => "warn",
        "info" | "information" | "notice" | "i" | "n" => "info",
        "debug" | "trace" | "verbose" | "d" | "t" | "v" => "debug",
        _ => "",
    }
}

/// The first level word in the line. Upper-case words count anywhere; lower- and title-case ones
/// only in log shapes (`error:`, `[warn]`, `error[E0308]`), so prose does not.
fn words(line: &str) -> &'static str {
    let bytes = line.as_bytes();
    let mut start = 0;
    while start < bytes.len() {
        if !bytes[start].is_ascii_alphabetic() {
            start += 1;
            continue;
        }
        let mut end = start;
        while end < bytes.len() && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_') {
            end += 1;
        }
        let word = &line[start..end];
        let before = if start > 0 { bytes[start - 1] } else { b' ' };
        let after = bytes.get(end).copied().unwrap_or(b' ');
        let shaped = after == b':' || (before == b'[' && after == b']') || (before == b'<' && after == b'>') || after == b'[';
        let found = match word {
            "ERROR" | "ERR" | "FATAL" | "CRITICAL" | "CRIT" | "PANIC" | "FAILED" | "FAIL" | "EMERG" => "error",
            "panic" | "panicked" | "Traceback" => "error",
            "WARN" | "WARNING" => "warn",
            "INFO" | "NOTICE" => "info",
            "DEBUG" | "TRACE" => "debug",
            "error" | "Error" | "fatal" | "Fatal" | "failed" | "Failed" if shaped => "error",
            "warning" | "Warning" | "warn" | "Warn" if shaped => "warn",
            "info" | "Info" | "notice" | "Notice" if shaped => "info",
            "debug" | "Debug" | "trace" | "Trace" if shaped => "debug",
            // TypeError: ..., java.lang.IllegalStateException
            _ if (word.ends_with("Error") && after == b':') || (word.ends_with("Exception") && word.len() > 9) => "error",
            _ => "",
        };
        if !found.is_empty() {
            return found;
        }
        start = end;
    }
    ""
}

/// `2026-10-29`, `15:04:05`, `Oct 29 15:04:05`, `[2026/...`, or a 10/13-digit epoch.
fn starts_with_timestamp(line: &str) -> bool {
    let line = line.trim_start_matches(['[', '(']);
    let b = line.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    if (0..4).all(digit) && matches!(b.get(4), Some(b'-' | b'/')) && digit(5) {
        return true;
    }
    if digit(0) && digit(1) && b.get(2) == Some(&b':') && digit(3) && digit(4) {
        return true;
    }
    let months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
    if months.iter().any(|m| line.starts_with(m)) && b.get(3) == Some(&b' ') {
        return true;
    }
    let run = b.iter().take_while(|c| c.is_ascii_digit()).count();
    (run == 10 || run == 13) && b.get(run).is_none_or(|c| !c.is_ascii_alphanumeric())
}

/// Whether a line's level passes a `level>=warn` / `level>=error` filter.
pub fn at_least(level: &str, min: &str) -> bool {
    let rank = |level: &str| match level {
        "error" => 3,
        "warn" => 2,
        "info" => 1,
        _ => 0,
    };
    rank(level) >= rank(min)
}

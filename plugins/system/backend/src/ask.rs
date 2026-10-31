//! `system.ask`: the Mac security skills' `macsec` words (`check <area>…`, `cve <id>`, `areas`),
//! answered inside the app. The terminal's chat flow hands the model's `macsec` command here
//! instead of running it in a shell, so a check uses the plugin's own baselines and feeds in the
//! graph, with nothing to pass between processes. The text is written for a small local model to
//! read and relay: compact, plain, capped.

use crate::graph;
use crate::sweep::Area;
use crate::util::{duration_text, plural, shorten};
use cc_protocol::contracts::system::{CveReport, SweepReport};
use std::collections::BTreeSet;
use serde_json::json;
use std::time::Duration;

/// What the terminal's model reads of a command's output.
pub const MODEL_CHARS: usize = 3900;
/// A check the model asks for answers within this; slower areas show the daily sweep's findings.
const WITHIN: Duration = Duration::from_secs(15);

pub const USAGE: &str = "usage:
  macsec check <area>... [--within <s>] [--full]
      Run the security sweep's checks for some areas (`all` for every one). An area not done
      within 15 s (or --within) shows the last sweep's findings; --full waits for every one.
  macsec cve <ID>
      Look up a CVE, GHSA, RUSTSEC, PYSEC, MAL or GO advisory and check it against this Mac.
  macsec weakness <words>
      What on this Mac has a known flaw of one kind (sql injection, xss, path traversal, CWE-89 …).
  macsec areas
      List the areas.";

/// What the words ask for.
pub enum Request {
    Check { areas: Vec<Area>, within: Option<Duration> },
    Cve(String),
    Weakness(String),
    Areas,
    Help,
}

/// The words after `macsec`; `Err` is what is wrong with them.
pub fn parse(args: &[String]) -> Result<Request, String> {
    let Some((command, args)) = args.split_first() else { return Ok(Request::Help) };
    match command.as_str() {
        "check" => {
            let (mut names, mut within, mut full) = (Vec::new(), Some(WITHIN), false);
            let mut rest = args.iter();
            while let Some(arg) = rest.next() {
                match arg.as_str() {
                    "--full" => full = true,
                    "--within" => match rest.next().and_then(|s| s.parse::<u64>().ok()).filter(|s| *s > 0) {
                        Some(seconds) => within = Some(Duration::from_secs(seconds)),
                        None => return Err("--within needs a number of seconds".into()),
                    },
                    flag if flag.starts_with('-') => return Err(format!("unknown option {flag}")),
                    name => names.push(name.to_owned()),
                }
            }
            Ok(Request::Check { areas: Area::parse(&names)?, within: if full { None } else { within } })
        }
        "cve" => match args {
            [id] => Ok(Request::Cve(id.clone())),
            [] => Err("which advisory: macsec cve CVE-2024-3094".into()),
            _ => Err("one advisory id at a time".into()),
        },
        "weakness" if args.is_empty() => Err("which kind of flaw: macsec weakness sql injection".into()),
        "weakness" => Ok(Request::Weakness(args.join(" "))),
        "areas" => Ok(Request::Areas),
        "help" | "--help" | "-h" => Ok(Request::Help),
        other => Err(format!("unknown command {other}")),
    }
}

pub fn areas_text() -> String {
    let mut out: String = Area::ALL.iter().map(|area| format!("{:<12} {} (also: {})\n", area.name(), area.about(), area.aliases().join(", "))).collect();
    out.push_str(&format!("{:<12} every area above\n", "all"));
    out
}

/// A check's text, with the knowledge notes for its findings from `notes` (Markdown) in the room
/// left: the model reads at most [`MODEL_CHARS`], findings first, the notes cut at a line.
pub fn check_answer(areas: &[Area], report: &SweepReport, notes: Option<&str>) -> String {
    let mut text = check_text(areas, report);
    if let Some(markdown) = notes {
        let notes = notes_text(markdown, report);
        let room = MODEL_CHARS.saturating_sub(text.len());
        if notes.len() <= room {
            text.push_str(&notes);
        } else if let Some(end) = notes[..notes.floor_char_boundary(room.saturating_sub(40))].rfind('\n') {
            text.push_str(&notes[..=end]);
            text.push_str("(more notes did not fit)\n");
        }
    }
    text
}

/// `4.2s`, or `2m05s` from a minute on.
fn seconds(ms: u64) -> String {
    if ms < 60_000 { format!("{:.1}s", ms as f64 / 1000.0) } else { duration_text(ms) }
}

/// The findings worth showing: not ignored, worst first (the report is sorted).
fn shown(report: &SweepReport) -> impl Iterator<Item = &cc_protocol::contracts::system::Finding> {
    report.findings.iter().filter(|f| !f.ignored)
}

fn check_text(areas: &[Area], report: &SweepReport) -> String {
    let names = if areas.len() == Area::ALL.len() { "all".to_owned() } else { areas.iter().map(|a| a.name()).collect::<Vec<_>>().join(", ") };
    let findings: Vec<_> = shown(report).collect();
    let ignored = report.findings.len() - findings.len();
    let mut counts = Vec::new();
    for severity in ["high", "medium", "low", "info"] {
        let n = findings.iter().filter(|f| f.severity == severity).count();
        if n > 0 {
            counts.push(format!("{n} {severity}"));
        }
    }
    let summary = if findings.is_empty() { "no findings".to_owned() } else { format!("{} ({})", plural(findings.len(), "finding", "findings"), counts.join(", ")) };
    let mut out = format!("SECURITY CHECK: {names} · {summary} · {}\n", seconds(report.duration_ms));

    let mut listed = 0;
    for (i, finding) in findings.iter().enumerate() {
        if out.len() > 2400 || listed == 15 {
            break;
        }
        out.push_str(&format!(
            "{}. [{}] {} · {}: {}\n",
            i + 1,
            finding.severity.to_uppercase(),
            Area::of(finding).name(),
            finding.source,
            shorten(&finding.text, 300)
        ));
        if let Some(fix) = &finding.fix {
            out.push_str(&format!("   fix (offered, not run): {}\n", shorten(fix, 200)));
        }
        listed += 1;
    }
    if findings.len() > listed {
        out.push_str(&format!("… and {} not shown (--json lists all).\n", plural(findings.len() - listed, "more finding", "more findings")));
    }
    if ignored > 0 {
        out.push_str(&format!("{} you marked as ignored left out.\n", plural(ignored, "finding", "findings")));
    }
    // Areas that missed the deadline, in full: the model should say these are older results.
    let (late, checked): (Vec<&String>, Vec<&String>) = report.checked.iter().partition(|c| c.contains(": from the sweep of "));
    for line in late {
        out.push_str(&format!("Not fresh: {line}\n"));
    }
    if !checked.is_empty() {
        out.push_str(&format!("Checked: {}\n", shorten(&checked.iter().map(|c| c.as_str()).collect::<Vec<_>>().join("; "), 450)));
    }
    if !report.skipped.is_empty() {
        out.push_str(&format!("Not checked: {}\n", shorten(&report.skipped.join("; "), 450)));
    }
    out
}

/// The note for each distinct finding source (else kind), from `## id, alias, …` sections.
fn notes_text(markdown: &str, report: &SweepReport) -> String {
    let mut sections: Vec<(Vec<String>, String)> = Vec::new();
    for line in markdown.lines() {
        if let Some(heading) = line.strip_prefix("## ") {
            sections.push((heading.split(',').map(|n| n.trim().to_lowercase()).filter(|n| !n.is_empty()).collect(), String::new()));
        } else if let Some((_, body)) = sections.last_mut()
            && !line.trim().is_empty()
        {
            if !body.is_empty() {
                body.push(' ');
            }
            body.push_str(line.trim());
        }
    }
    let mut seen = BTreeSet::new();
    let mut notes = Vec::new();
    for finding in shown(report).take(15) {
        let wanted = [finding.source.to_lowercase(), finding.kind.to_lowercase()];
        let Some((names, body)) = wanted.iter().find_map(|w| sections.iter().find(|(names, _)| names.contains(w))) else { continue };
        if seen.insert(names[0].clone()) {
            notes.push(format!("[{}] {}", names[0], shorten(body, 400)));
        }
        if notes.len() == 6 {
            break;
        }
    }
    if notes.is_empty() { String::new() } else { format!("NOTES\n{}\n", notes.join("\n")) }
}

pub fn cve_text(r: &CveReport) -> String {
    let mut out = format!("{}\n", r.verdict_text);
    let title = if r.title.is_empty() { String::new() } else { format!(": {}", r.title) };
    let aliases = if r.aliases.is_empty() { String::new() } else { format!(" (also {})", r.aliases.iter().take(4).cloned().collect::<Vec<_>>().join(", ")) };
    out.push_str(&format!("{}{aliases}{title}\n", r.id));
    let mut facts = Vec::new();
    if let Some(c) = &r.cvss {
        facts.push(if c.score > 0.0 {
            format!("CVSS {:.1} {} (v{})", c.score, c.severity.to_lowercase(), c.version)
        } else {
            format!("severity {}", c.severity.to_lowercase())
        });
    }
    match &r.kev {
        Some(k) => facts.push(format!(
            "CISA KEV: exploited in the wild{}{}{}",
            if k.added.is_empty() { String::new() } else { format!(", listed {}", k.added) },
            if k.due.is_empty() { String::new() } else { format!(", fix due {}", k.due) },
            if k.ransomware { ", used in ransomware" } else { "" }
        )),
        None if r.id.starts_with("CVE-") || r.aliases.iter().any(|a| a.starts_with("CVE-")) => facts.push("not in CISA KEV".into()),
        None => {}
    }
    if let Some(e) = &r.epss {
        facts.push(format!("EPSS {:.1}% chance of exploitation in 30 days (higher than {:.1}% of CVEs)", e.score * 100.0, (e.percentile * 1000.0).floor() / 10.0));
    }
    if !r.published.is_empty() {
        facts.push(format!("published {}", r.published));
    }
    if !r.cwe.is_empty() {
        facts.push(r.cwe.iter().take(3).cloned().collect::<Vec<_>>().join(", "));
    }
    if !facts.is_empty() {
        out.push_str(&format!("Facts: {}\n", facts.join(" · ")));
    }
    if !r.summary.is_empty() {
        out.push_str(&format!("Summary: {}\n", shorten(&r.summary, 400)));
    }
    if !r.matches.is_empty() {
        out.push_str("On this Mac:\n");
        for m in r.matches.iter().take(8) {
            let version = if m.version.is_empty() { String::new() } else { format!(" {}", m.version) };
            let place = if m.place.is_empty() || m.place == "this Mac" { String::new() } else { format!(" ({})", m.place) };
            out.push_str(&format!("- [{}] {}{version}{place}: {}\n", m.verdict, m.what, shorten(&m.why, 220)));
            if let Some(fix) = &m.fix {
                out.push_str(&format!("  fix (offered, not run): {}\n", shorten(fix, 160)));
            }
        }
        if r.matches.len() > 8 {
            out.push_str(&format!("… and {} (--json lists all).\n", plural(r.matches.len() - 8, "more match", "more matches")));
        }
    }
    if !r.affects.is_empty() {
        out.push_str("The advisory covers:\n");
        for a in r.affects.iter().take(6) {
            out.push_str(&format!("- {} ({}): {}\n", a.what, a.source, shorten(&a.versions, 120)));
        }
        if r.affects.len() > 6 {
            out.push_str(&format!("… and {} more.\n", r.affects.len() - 6));
        }
    }
    if !r.references.is_empty() {
        out.push_str("References:\n");
        for reference in r.references.iter().take(3) {
            out.push_str(&format!("- {}\n", reference.url));
        }
    }
    if !r.checked.is_empty() {
        out.push_str(&format!("Checked: {}\n", shorten(&r.checked.join("; "), 400)));
    }
    if !r.skipped.is_empty() {
        out.push_str(&format!("Not checked: {}\n", shorten(&r.skipped.join("; "), 400)));
    }
    out
}

/// Kinds of flaw in plain words, and their CWE ids.
const WEAKNESSES: &[(&str, &[&str], &[&str])] = &[
    ("SQL injection", &["sql"], &["CWE-89"]),
    ("cross-site scripting", &["xss", "cross-site scripting", "cross site scripting"], &["CWE-79"]),
    ("command or code injection", &["command injection", "shell injection", "code injection", "remote code execution", "rce"], &["CWE-77", "CWE-78", "CWE-94"]),
    ("path traversal", &["traversal"], &["CWE-22", "CWE-23"]),
    ("unsafe deserialization", &["deserializ"], &["CWE-502"]),
    ("server-side request forgery", &["ssrf", "request forgery"], &["CWE-918", "CWE-352"]),
    ("XML external entities", &["xxe", "xml external"], &["CWE-611"]),
    ("memory corruption", &["buffer overflow", "memory corruption", "out-of-bounds", "out of bounds", "use after free", "use-after-free", "overflow"], &["CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-416", "CWE-190"]),
    ("authentication bypass", &["authentication", "auth bypass", "login bypass"], &["CWE-287", "CWE-306", "CWE-798"]),
    ("privilege escalation", &["privilege", "access control", "authorization"], &["CWE-269", "CWE-284", "CWE-285", "CWE-862", "CWE-863"]),
    ("denial of service", &["denial of service", "dos", "redos", "resource exhaustion"], &["CWE-400", "CWE-770", "CWE-1333"]),
    ("prototype pollution", &["prototype pollution"], &["CWE-1321"]),
    ("information leak", &["information disclosure", "information exposure", "leak"], &["CWE-200"]),
    ("certificate validation", &["certificate", "tls", "ssl"], &["CWE-295"]),
];

/// What the graph knows affects this Mac with flaws of the kind `words` name.
pub async fn weakness_text(words: &str) -> (String, i32) {
    let asked = words.to_lowercase();
    let mut names = Vec::new();
    let mut ids: BTreeSet<String> = asked.split(|c: char| c.is_whitespace() || c == ',').filter(|w| w.starts_with("cwe-")).map(str::to_uppercase).collect();
    let said_words: Vec<&str> = asked.split(|c: char| !c.is_alphanumeric() && c != '-').filter(|w| !w.is_empty()).collect();
    // A cue of several words is a phrase; one word starts a word ("deserializ…"), never sits inside one.
    let said = |cue: &str| if cue.contains(' ') { asked.contains(cue) } else { said_words.iter().any(|w| w.starts_with(cue)) };
    for (name, cues, cwes) in WEAKNESSES {
        if cues.iter().any(|cue| said(cue)) {
            names.push(*name);
            ids.extend(cwes.iter().map(|id| (*id).to_owned()));
        }
    }
    if ids.is_empty() {
        let known: Vec<&str> = WEAKNESSES.iter().map(|(name, _, _)| *name).collect();
        return (format!("macsec: no kind of flaw matches \"{words}\". Known: {}, or a CWE id.\n", known.join(", ")), 2);
    }
    let rows = match graph::query_all(
        "MATCH (a:Advisory)-[e:AFFECTS]->(t) OPTIONAL MATCH (r:Repo)-[:DEPENDS_ON]->(t) \
         RETURN a.key, a.title, a.cwe, a.kev, t.key, e.verdict, e.version, e.fixed_in, e.fix, collect(r.key)",
        json!({}),
    )
    .await
    {
        Ok(rows) => rows,
        Err(error) => return (format!("macsec: the memory could not be read: {error}\n"), 1),
    };
    let label = if names.is_empty() { ids.iter().cloned().collect::<Vec<_>>().join(", ") } else { names.join(", ") };
    let mut out = format!("WEAKNESS: {label} ({})\n", ids.iter().cloned().collect::<Vec<_>>().join(", "));
    let (mut affected, mut clear) = (Vec::new(), BTreeSet::new());
    for row in &rows {
        if !graph::texts(&row[2]).iter().any(|c| ids.contains(c)) {
            continue;
        }
        if graph::text(&row[5]) == "affected" {
            affected.push(row);
        } else {
            clear.insert(graph::text(&row[0]));
        }
    }
    out.push_str(&format!("Affects this Mac: {}\n", affected.len()));
    for (i, row) in affected.iter().take(12).enumerate() {
        let mut line = format!("{}. {}{} {} {}", i + 1, graph::text(&row[0]), if row[3].as_bool() == Some(true) { " [exploited, CISA KEV]" } else { "" }, graph::text(&row[4]), graph::text(&row[6]));
        let fixed_in = graph::text(&row[7]);
        if !fixed_in.is_empty() {
            line.push_str(&format!(", fixed in {fixed_in}"));
        }
        let repos = graph::texts(&row[9]);
        if !repos.is_empty() {
            line.push_str(&format!(" · used by {}", repos.iter().take(3).map(|r| crate::util::tilde(std::path::Path::new(r))).collect::<Vec<_>>().join(", ")));
        }
        out.push_str(&line);
        out.push('\n');
        if let Some(fix) = row[8].as_str().filter(|f| !f.is_empty()) {
            out.push_str(&format!("   fix (offered, not run): {}\n", shorten(fix, 160)));
        }
        out.push_str(&format!("   {}\n", shorten(&graph::text(&row[1]), 160)));
    }
    if affected.len() > 12 {
        out.push_str(&format!("… and {} more.\n", affected.len() - 12));
    }
    if !clear.is_empty() {
        out.push_str(&format!("Checked here and not affecting this Mac: {}.\n", plural(clear.len(), "advisory", "advisories")));
    }
    out.push_str("Only advisories CortexTerm has already compared with this Mac are known; `macsec check packages updates` looks again.\n");
    (out, 0)
}
